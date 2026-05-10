package cboxidtokens

import (
	"context"
	"sync"
	"time"
)

// Cache is the storage interface CboxIdTokens uses to remember
// fetched tokens between calls. Bytes in / bytes out — the client
// owns serialisation so production deployments can plug in any
// store (Redis, Memcached, Hazelcast, in-memory) without us
// caring about the wire format.
//
// Implementations MUST honour the TTL passed to Set and SHOULD
// auto-evict on expiry. Get returns (nil, false) for misses or
// expired entries.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// InMemoryCache is a process-local Cache backed by a sync.Map plus
// a wall-clock TTL check. Suitable for single-instance deployments
// or test wiring; production with multiple replicas should use a
// shared store like Redis.
type InMemoryCache struct {
	mu    sync.RWMutex
	items map[string]inMemoryEntry
}

type inMemoryEntry struct {
	value     []byte
	expiresAt time.Time
}

// NewInMemoryCache returns a ready-to-use in-process cache.
func NewInMemoryCache() *InMemoryCache {
	return &InMemoryCache{items: make(map[string]inMemoryEntry)}
}

func (c *InMemoryCache) Get(_ context.Context, key string) ([]byte, bool) {
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		// Re-check under write lock to avoid concurrent races.
		if entry, ok := c.items[key]; ok && time.Now().After(entry.expiresAt) {
			delete(c.items, key)
		}
		c.mu.Unlock()
		return nil, false
	}

	return entry.value, true
}

func (c *InMemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = inMemoryEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (c *InMemoryCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
	return nil
}
