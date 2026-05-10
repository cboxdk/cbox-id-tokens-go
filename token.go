// Package cboxidtokens is the Go counterpart of the PHP
// cboxdk/cbox-id-tokens package — a service-to-service OAuth helper
// for callers of id-issued tokens, implementing the contract in
// cbox-infra/docs/SERVICE_AUTH.md.
//
// Cache keys are SHA-256-hashed by (client_id, audience,
// sorted-deduped-scopes) and prefixed with "cbox:svc-token:" — the
// hash bytes are identical to the PHP version's, so PHP and Go
// services sharing a Redis instance hit the same slot for the same
// (client, audience, scope) triple.
package cboxidtokens

import "time"

// ServiceToken is the result of a successful token fetch. Callers
// attach Bearer to outbound HTTP requests; ExpiresAt is the wall-
// clock instant the token is no longer valid.
type ServiceToken struct {
	Bearer    string    `json:"bearer"`
	ExpiresAt time.Time `json:"expires_at"`
	Audience  string    `json:"audience"`
	Scopes    []string  `json:"scopes"`
}

// IsExpired reports whether the token has reached or passed its
// ExpiresAt instant. Optional now lets tests inject a clock; the
// zero value uses time.Now().
func (t *ServiceToken) IsExpired(now ...time.Time) bool {
	current := time.Now()
	if len(now) > 0 {
		current = now[0]
	}
	return !current.Before(t.ExpiresAt)
}
