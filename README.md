# cbox-id-tokens-go

Go counterpart of the PHP [`cboxdk/cbox-id-tokens`](https://github.com/cboxdk/cbox-id-tokens)
package. Service-to-service OAuth helper for callers of id-issued tokens, implementing
the contract in [cbox-infra/docs/SERVICE_AUTH.md](https://github.com/cboxdk/cbox-infra/blob/main/docs/SERVICE_AUTH.md).

Cache keys are SHA-256-hashed by `(client_id, audience, sorted-deduped-scopes)`
and prefixed with `cbox:svc-token:` — **byte-identical to the PHP version's**, so
PHP and Go services sharing a Redis hit the same slot for the same triple.

## Install

```bash
go get github.com/cboxdk/cbox-id-tokens-go
```

## Use

```go
import (
    "context"
    "net/http"

    cboxidtokens "github.com/cboxdk/cbox-id-tokens-go"
)

client := cboxidtokens.New(
    cboxidtokens.WithTokenEndpoint("https://id.cbox.systems/oauth/token"),
    cboxidtokens.WithClientCredentials("vault-prod", os.Getenv("CBOX_ID_CLIENT_SECRET")),
)

token, err := client.
    ForAudience("notifications.cbox.systems").
    WithScopes("notifications.publish").
    Fetch(ctx)
if err != nil {
    return err
}

req, _ := http.NewRequestWithContext(ctx, "POST", "https://notifications.cbox.systems/api/v1/events", body)
req.Header.Set("Authorization", "Bearer "+token.Bearer)
```

### On a 401 from upstream

```go
audience := "notifications.cbox.systems"
scopes := []string{"notifications.publish"}

token, _ := client.ForAudience(audience).WithScopes(scopes...).Fetch(ctx)
resp, _ := httpClient.Do(req)

if resp.StatusCode == http.StatusUnauthorized {
    _ = client.Invalidate(ctx, audience, scopes)
    token, _ = client.ForAudience(audience).WithScopes(scopes...).Fetch(ctx)
    // retry once
}
```

A second 401 after `Invalidate` is a hard failure — let it propagate.

## Cache backends

Default cache is `InMemoryCache` (process-local, sync.Map). For production with multiple
replicas, plug in any `Cache` impl:

```go
type Cache interface {
    Get(ctx context.Context, key string) ([]byte, bool)
    Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
}

client := cboxidtokens.New(
    /* ... */,
    cboxidtokens.WithCache(myRedisAdapter),
)
```

A Redis adapter using `github.com/redis/go-redis/v9` is straightforward — Get
returns `(value, true)` on hit, `(nil, false)` on miss / expired.

## Errors

All recoverable errors return `*TokenFetchError`:

```go
import "errors"

var fe *cboxidtokens.TokenFetchError
if errors.As(err, &fe) {
    log.Printf("token fetch failed: status=%d upstream=%q audience=%s",
        fe.HTTPStatus, fe.UpstreamError, fe.Audience)
}
```

Network errors are also wrapped — `errors.Is(err, context.DeadlineExceeded)` and
`errors.As(err, &fe.Err)` both work via `Unwrap`.

## Testing

```bash
make test         # plain
make test-race    # race detector + coverage
```

## License

MIT
