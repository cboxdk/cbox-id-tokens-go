package cboxidtokens

// ComputeCacheKey is exposed only to the test package so we can
// lock the cross-language hash format byte-for-byte against the
// PHP package.
func ComputeCacheKey(c *Client, audience string, scopes []string) string {
	return c.cacheKey(audience, scopes)
}
