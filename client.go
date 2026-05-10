package cboxidtokens

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// ttlSafetyMargin keeps the cached entry from ever serving a
	// soon-to-expire token. Cache TTL = expires_in - margin.
	ttlSafetyMargin = 60 * time.Second

	// cacheKeyPrefix matches the PHP package byte-for-byte so PHP
	// and Go consumers sharing a Redis hit the same slot.
	cacheKeyPrefix = "cbox:svc-token:"

	// defaultDialTimeout is the connect-only budget. Token endpoints
	// in our infra resolve sub-100ms and connect sub-50ms; 5s leaves
	// generous slack for the bad-day case without blocking the
	// outbound call indefinitely on a network partition.
	defaultDialTimeout = 5 * time.Second

	// defaultTotalTimeout is the connect+read budget on the http.Client
	// itself, matching the PHP package's `connectTimeout(5)->timeout(10)`
	// combination so cross-language callers see uniform behaviour.
	defaultTotalTimeout = 10 * time.Second
)

// Client is the entry point for fetching and invalidating service
// tokens. Construct one per service via New + functional options;
// it's safe to share across goroutines.
type Client struct {
	tokenEndpoint  string
	clientID       string
	clientSecret   string
	httpClient     *http.Client
	cache          Cache
	now            func() time.Time
	sf             singleflight.Group
	allowInsecure  bool
	httpClientUser bool // true when the caller supplied a custom *http.Client
}

// Option configures a Client at construction time. Options that
// cover the same field follow last-write-wins semantics.
type Option func(*Client)

// New returns a configured Client. Required options:
// WithTokenEndpoint, WithClientCredentials.
//
// Defaults:
//   - HTTP transport with 5s dial timeout + 10s total timeout
//   - in-memory cache (NewInMemoryCache)
//   - time.Now as clock
//
// SECURITY: tokenEndpoint MUST be https://. http:// is rejected
// unless WithAllowInsecure was passed AND the host is loopback
// (localhost / 127.0.0.1 / ::1). Mirrors cbox-id-tokens (PHP).
//
// Returns an error when validation fails so the misconfig surfaces
// at boot rather than on the first outbound call.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		cache: NewInMemoryCache(),
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}

	if c.tokenEndpoint == "" {
		return nil, errors.New("cbox-id-tokens-go: WithTokenEndpoint is required")
	}
	if c.clientID == "" || c.clientSecret == "" {
		return nil, errors.New("cbox-id-tokens-go: WithClientCredentials is required")
	}
	if err := assertSecureScheme(c.tokenEndpoint, c.allowInsecure); err != nil {
		return nil, err
	}

	if c.httpClient == nil {
		c.httpClient = newDefaultHTTPClient()
	}

	return c, nil
}

// assertSecureScheme rejects http:// tokenEndpoints unless the
// caller explicitly opted in via WithAllowInsecure AND the host is
// loopback. Mirrors the PHP package's check verbatim.
func assertSecureScheme(rawURL string, allowInsecure bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("cbox-id-tokens-go: tokenEndpoint is not a valid URL: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "https" {
		return nil
	}

	host := strings.ToLower(parsed.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if allowInsecure && scheme == "http" && loopback {
		return nil
	}

	return fmt.Errorf(
		"cbox-id-tokens-go: tokenEndpoint must use https:// (got: %s); "+
			"for local dev pass WithAllowInsecure() with http://localhost — "+
			"never with a public hostname",
		rawURL,
	)
}

// newDefaultHTTPClient builds the standard transport: 5s dial,
// 10s total. The split separates "couldn't connect" (retry-friendly)
// from "server is slow" (probably needs investigation), and matches
// the PHP package's connectTimeout(5)->timeout(10) so cross-language
// callers behave the same on the network.
func newDefaultHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   defaultDialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   defaultTotalTimeout,
	}
}

// WithTokenEndpoint sets the absolute URL of id's /oauth/token.
func WithTokenEndpoint(u string) Option {
	return func(c *Client) { c.tokenEndpoint = u }
}

// WithClientCredentials sets the OAuth client_id + client_secret
// the helper presents on every grant request.
func WithClientCredentials(id, secret string) Option {
	return func(c *Client) {
		c.clientID = id
		c.clientSecret = secret
	}
}

// WithHTTPClient swaps the default HTTP client (5s dial / 10s total)
// for a caller-supplied one. Use to inject custom transports, OTel
// instrumentation, retries, or shorter / longer timeouts. Passing
// an *http.Client with Timeout==0 means no overall budget; you
// almost certainly want a non-zero timeout in production.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		c.httpClient = h
		c.httpClientUser = true
	}
}

// WithAllowInsecure permits an http://localhost (or 127.0.0.1 / ::1)
// tokenEndpoint. Required for local-dev fixtures and httptest. Does
// NOT bypass the scheme check for public hosts — those still require
// https://. Without this option an http:// endpoint fails New().
func WithAllowInsecure() Option {
	return func(c *Client) { c.allowInsecure = true }
}

// WithCache swaps the default in-memory cache for any Cache impl
// (Redis, Memcached, …). Production with multiple replicas should
// use a shared store so each pod doesn't burn its own /oauth/token
// roundtrip on cold starts.
func WithCache(cache Cache) Option {
	return func(c *Client) { c.cache = cache }
}

// WithClock injects a now-function. Tests set this to drive
// deterministic TTL behaviour without sleeps.
func WithClock(now func() time.Time) Option {
	return func(c *Client) { c.now = now }
}

// ForAudience starts a fluent token request for the given target
// service. Chain WithScopes and Fetch.
func (c *Client) ForAudience(audience string) *Request {
	return &Request{client: c, audience: audience}
}

// Invalidate forgets the cached token for a (audience, scopes)
// pair. Call this after a 401 from the upstream so the next fetch
// goes back to id's /oauth/token instead of replaying a stale
// token.
func (c *Client) Invalidate(ctx context.Context, audience string, scopes []string) error {
	return c.cache.Delete(ctx, c.cacheKey(audience, scopes))
}

// fetchToken runs the cache → single-flight → endpoint pipeline.
// Called via Request.Fetch.
func (c *Client) fetchToken(ctx context.Context, audience string, scopes []string) (*ServiceToken, error) {
	cacheKey := c.cacheKey(audience, scopes)

	// Fast path: cache hit + not expired.
	if data, ok := c.cache.Get(ctx, cacheKey); ok {
		if token, err := decodeToken(data); err == nil && !token.IsExpired(c.now()) {
			return token, nil
		}
	}

	// Single-flight: only one goroutine per cache key talks to the
	// token endpoint at a time. Followers wait, then read the
	// already-populated cache entry.
	result, err, _ := c.sf.Do(cacheKey, func() (any, error) {
		// Re-check after acquiring — a concurrent leader may have
		// populated the cache while we waited.
		if data, ok := c.cache.Get(ctx, cacheKey); ok {
			if token, err := decodeToken(data); err == nil && !token.IsExpired(c.now()) {
				return token, nil
			}
		}

		token, err := c.fetchFromEndpoint(ctx, audience, scopes)
		if err != nil {
			return nil, err
		}

		ttl := token.ExpiresAt.Sub(c.now()) - ttlSafetyMargin
		if ttl < time.Second {
			ttl = time.Second
		}
		data, err := json.Marshal(token)
		if err == nil {
			_ = c.cache.Set(ctx, cacheKey, data, ttl)
		}
		return token, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(*ServiceToken), nil
}

// fetchFromEndpoint posts a client_credentials grant request to
// id's /oauth/token and parses the response into a ServiceToken.
// Errors are wrapped in TokenFetchError so callers see a uniform
// contract.
func (c *Client) fetchFromEndpoint(ctx context.Context, audience string, scopes []string) (*ServiceToken, error) {
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"scope":         {strings.Join(scopes, " ")},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, strings.NewReader(body))
	if err != nil {
		return nil, &TokenFetchError{
			Audience: audience,
			Message:  "construct request: " + err.Error(),
			Err:      err,
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &TokenFetchError{
			Audience: audience,
			Message:  "post to token endpoint: " + err.Error(),
			Err:      err,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		upstreamError := ""
		var parsed map[string]any
		if json.Unmarshal(respBody, &parsed) == nil {
			if v, ok := parsed["error"].(string); ok {
				upstreamError = v
			}
		}
		return nil, &TokenFetchError{
			Audience:      audience,
			HTTPStatus:    resp.StatusCode,
			UpstreamError: upstreamError,
			Message:       fmt.Sprintf("token endpoint returned HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200)),
		}
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, &TokenFetchError{
			Audience:   audience,
			HTTPStatus: resp.StatusCode,
			Message:    "decode token response: " + err.Error(),
			Err:        err,
		}
	}

	if payload.AccessToken == "" || payload.ExpiresIn <= 0 {
		return nil, &TokenFetchError{
			Audience:   audience,
			HTTPStatus: resp.StatusCode,
			Message:    "token endpoint returned a malformed response (missing access_token or expires_in)",
		}
	}

	return &ServiceToken{
		Bearer:    payload.AccessToken,
		ExpiresAt: c.now().Add(time.Duration(payload.ExpiresIn) * time.Second),
		Audience:  audience,
		Scopes:    append([]string(nil), scopes...),
	}, nil
}

// cacheKey produces sha256(client_id|audience|sorted-deduped-scopes)
// hex-encoded with the shared "cbox:svc-token:" prefix. Identical
// material/format to the PHP package so cross-language Redis
// tenancy hits the same slot for the same (client, audience, scope)
// triple.
func (c *Client) cacheKey(audience string, scopes []string) string {
	normalized := dedupeAndSort(scopes)
	material := c.clientID + "|" + audience + "|" + strings.Join(normalized, ",")
	sum := sha256.Sum256([]byte(material))
	return cacheKeyPrefix + hex.EncodeToString(sum[:])
}

func dedupeAndSort(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, exists := seen[s]; exists {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func decodeToken(data []byte) (*ServiceToken, error) {
	var t ServiceToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
