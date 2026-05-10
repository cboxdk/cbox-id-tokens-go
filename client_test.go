package cboxidtokens_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	cboxidtokens "github.com/cboxdk/cbox-id-tokens-go"
)

const (
	testClientID     = "test-client"
	testClientSecret = "test-secret"
)

// fakeTokenServer returns an httptest server that echoes a
// configurable token + expires_in. Each call increments hits, so
// tests can assert how many round-trips happened.
func fakeTokenServer(t *testing.T, bearer string, expiresIn int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("grant_type") != "client_credentials" {
			http.Error(w, "wrong grant", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":   "Bearer",
			"access_token": bearer,
			"expires_in":   expiresIn,
		})
	}))
	t.Cleanup(server.Close)
	return server, hits
}

func newClient(t *testing.T, endpoint string, opts ...cboxidtokens.Option) *cboxidtokens.Client {
	t.Helper()
	base := []cboxidtokens.Option{
		cboxidtokens.WithTokenEndpoint(endpoint),
		cboxidtokens.WithClientCredentials(testClientID, testClientSecret),
	}
	return cboxidtokens.New(append(base, opts...)...)
}

func TestFluentAPIFetchesToken(t *testing.T) {
	server, hits := fakeTokenServer(t, "the-token", 600)
	c := newClient(t, server.URL)

	tok, err := c.ForAudience("notifications.cbox.systems").
		WithScopes("notifications.publish").
		Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if tok.Bearer != "the-token" {
		t.Errorf("Bearer = %q, want %q", tok.Bearer, "the-token")
	}
	if tok.Audience != "notifications.cbox.systems" {
		t.Errorf("Audience = %q", tok.Audience)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("hits = %d, want 1", got)
	}
}

func TestRepeatedFetchHitsCacheNotEndpoint(t *testing.T) {
	server, hits := fakeTokenServer(t, "once-only", 600)
	c := newClient(t, server.URL)
	ctx := t.Context()

	for range 3 {
		_, err := c.ForAudience("a.cbox.systems").WithScopes("s").Fetch(ctx)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("hits = %d, want 1 (cache should serve repeats)", got)
	}
}

func TestScopeOrderAndDuplicatesShareCache(t *testing.T) {
	server, hits := fakeTokenServer(t, "tok", 600)
	c := newClient(t, server.URL)
	ctx := t.Context()

	// Order varies; duplicates included.
	calls := [][]string{
		{"id.usage.write", "id.audit.write"},
		{"id.audit.write", "id.usage.write"},
		{"id.audit.write", "id.audit.write", "id.usage.write"},
	}
	for _, scopes := range calls {
		if _, err := c.ForAudience("vault.cbox.systems").WithScopes(scopes...).Fetch(ctx); err != nil {
			t.Fatalf("Fetch %v: %v", scopes, err)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("hits = %d, want 1 (sort+dedupe should collapse)", got)
	}
}

func TestDifferentScopesProduceSeparateFetches(t *testing.T) {
	hits := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":   "Bearer",
			"access_token": "tok-" + strconv.Itoa(int(n)),
			"expires_in":   600,
		})
	}))
	t.Cleanup(server.Close)

	c := newClient(t, server.URL)
	ctx := t.Context()

	a, _ := c.ForAudience("x.cbox.systems").WithScopes("notifications.publish").Fetch(ctx)
	b, _ := c.ForAudience("x.cbox.systems").WithScopes("id.audit.write").Fetch(ctx)

	if a.Bearer == b.Bearer {
		t.Errorf("expected distinct bearers per scope set, got %q twice", a.Bearer)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits = %d, want 2", got)
	}
}

func TestInvalidateForcesRefetch(t *testing.T) {
	hits := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":   "Bearer",
			"access_token": "tok-" + strconv.Itoa(int(n)),
			"expires_in":   600,
		})
	}))
	t.Cleanup(server.Close)

	c := newClient(t, server.URL)
	ctx := t.Context()
	scopes := []string{"notifications.publish"}
	audience := "notifications.cbox.systems"

	first, _ := c.ForAudience(audience).WithScopes(scopes...).Fetch(ctx)
	if err := c.Invalidate(ctx, audience, scopes); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	second, _ := c.ForAudience(audience).WithScopes(scopes...).Fetch(ctx)

	if first.Bearer == second.Bearer {
		t.Errorf("expected new bearer after invalidate, got same %q", first.Bearer)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits = %d, want 2", got)
	}
}

func TestCacheTTLMatchesExpiryMinusSafetyMargin(t *testing.T) {
	server, hits := fakeTokenServer(t, "first", 600)
	t.Cleanup(server.Close)

	frozen := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	clock := &mutableClock{t: frozen}

	c := newClient(t, server.URL, cboxidtokens.WithClock(clock.Now))
	ctx := t.Context()

	if _, err := c.ForAudience("a.cbox.systems").WithScopes("s").Fetch(ctx); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// +5 min — well inside TTL (540s = 9 min). Cache hit.
	clock.Set(frozen.Add(5 * time.Minute))
	if _, err := c.ForAudience("a.cbox.systems").WithScopes("s").Fetch(ctx); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("hits at +5min = %d, want 1", got)
	}

	// +10 min — past TTL AND past expiresAt. Refetch.
	clock.Set(frozen.Add(10*time.Minute + time.Second))
	if _, err := c.ForAudience("a.cbox.systems").WithScopes("s").Fetch(ctx); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("hits at +10min = %d, want 2", got)
	}
}

func TestUpstream4xxSurfacesAsTokenFetchErrorWithStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_client",
			"error_description": "Authentication failed",
		})
	}))
	t.Cleanup(server.Close)

	c := newClient(t, server.URL)
	_, err := c.ForAudience("notifications.cbox.systems").
		WithScopes("notifications.publish").
		Fetch(t.Context())

	var fe *cboxidtokens.TokenFetchError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *TokenFetchError, got %T (%v)", err, err)
	}
	if fe.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("HTTPStatus = %d, want %d", fe.HTTPStatus, http.StatusUnauthorized)
	}
	if fe.UpstreamError != "invalid_client" {
		t.Errorf("UpstreamError = %q, want invalid_client", fe.UpstreamError)
	}
	if fe.Audience != "notifications.cbox.systems" {
		t.Errorf("Audience = %q", fe.Audience)
	}
}

func TestUpstream5xxSurfacesAsTokenFetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream blew up", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	c := newClient(t, server.URL)
	_, err := c.ForAudience("a.cbox.systems").WithScopes("s").Fetch(t.Context())

	var fe *cboxidtokens.TokenFetchError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *TokenFetchError, got %T", err)
	}
	if fe.HTTPStatus != http.StatusServiceUnavailable {
		t.Errorf("HTTPStatus = %d", fe.HTTPStatus)
	}
}

func TestMalformedResponseSurfacesAsTokenFetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type": "Bearer",
			"expires_in": 600,
			// access_token missing
		})
	}))
	t.Cleanup(server.Close)

	c := newClient(t, server.URL)
	_, err := c.ForAudience("a.cbox.systems").WithScopes("s").Fetch(t.Context())

	var fe *cboxidtokens.TokenFetchError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *TokenFetchError, got %T", err)
	}
}

func TestUnreachableEndpointSurfacesAsTokenFetchError(t *testing.T) {
	c := newClient(t, "http://127.0.0.1:1") // closed port

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)

	_, err := c.ForAudience("a.cbox.systems").WithScopes("s").Fetch(ctx)

	var fe *cboxidtokens.TokenFetchError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *TokenFetchError, got %T (%v)", err, err)
	}
	if fe.Err == nil {
		t.Errorf("expected wrapped Err, got nil")
	}
}

func TestCacheKeyMatchesPHPVersion(t *testing.T) {
	// Lock the SHA-256 digest format so PHP and Go consumers
	// sharing a Redis hit the same key for the same input.
	// Material: "test-client|notifications.cbox.systems|notifications.publish"
	// PHP: hash('sha256', $material) hex.
	c := cboxidtokens.New(
		cboxidtokens.WithTokenEndpoint("https://id.test/oauth/token"),
		cboxidtokens.WithClientCredentials(testClientID, testClientSecret),
	)
	got := cboxidtokens.ComputeCacheKey(c, "notifications.cbox.systems", []string{"notifications.publish"})

	// Verified against PHP: hash('sha256', "test-client|notifications.cbox.systems|notifications.publish")
	want := "cbox:svc-token:3160b97a1ecc7e798406d1ddfde6fef4c4ce792c5b2bce42da76e6b5a3644e16"
	if got != want {
		t.Errorf("cacheKey = %q,\n want   %q", got, want)
	}
}

// mutableClock is the test clock used to drive deterministic TTL.
type mutableClock struct {
	t time.Time
}

func (c *mutableClock) Now() time.Time { return c.t }
func (c *mutableClock) Set(t time.Time) { c.t = t }
