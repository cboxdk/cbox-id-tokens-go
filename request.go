package cboxidtokens

import "context"

// Request is the fluent builder returned by Client.ForAudience.
// Each call returns a new instance, so it's safe to stash a base
// Request and derive variants with different scope sets.
type Request struct {
	client   *Client
	audience string
	scopes   []string
}

// WithScopes sets the OAuth scope list this request will ask for.
// Returns a new Request — the receiver is not mutated.
func (r *Request) WithScopes(scopes ...string) *Request {
	dup := make([]string, len(scopes))
	copy(dup, scopes)
	return &Request{
		client:   r.client,
		audience: r.audience,
		scopes:   dup,
	}
}

// Fetch executes the request and returns a ServiceToken (cached
// or freshly minted). On any failure the returned error is a
// *TokenFetchError carrying audience + http context.
func (r *Request) Fetch(ctx context.Context) (*ServiceToken, error) {
	return r.client.fetchToken(ctx, r.audience, r.scopes)
}
