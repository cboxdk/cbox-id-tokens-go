package cboxidtokens

import "fmt"

// TokenFetchError is returned for any failure path in
// CboxIdTokens.Fetch. Callers can pull HTTPStatus / UpstreamError
// for retry / log decisions, or use errors.Is / errors.As against
// the wrapped Err for low-level inspection (e.g. *net.OpError,
// context.DeadlineExceeded).
type TokenFetchError struct {
	// Audience the failed call was for.
	Audience string

	// HTTPStatus is non-zero when the token endpoint returned a
	// 4xx/5xx. Zero on network / wrap errors.
	HTTPStatus int

	// UpstreamError is the OAuth2 error code from the response
	// body when present (invalid_client, invalid_scope, ...).
	UpstreamError string

	// Message is a human-readable summary; see Error() output.
	Message string

	// Err is the underlying cause when there is one.
	Err error
}

func (e *TokenFetchError) Error() string {
	switch {
	case e.HTTPStatus != 0 && e.UpstreamError != "":
		return fmt.Sprintf("cbox-id-tokens: %s (audience=%s, http=%d, upstream=%s)",
			e.Message, e.Audience, e.HTTPStatus, e.UpstreamError)
	case e.HTTPStatus != 0:
		return fmt.Sprintf("cbox-id-tokens: %s (audience=%s, http=%d)",
			e.Message, e.Audience, e.HTTPStatus)
	default:
		return fmt.Sprintf("cbox-id-tokens: %s (audience=%s)", e.Message, e.Audience)
	}
}

func (e *TokenFetchError) Unwrap() error {
	return e.Err
}
