package cache

import (
	"context"
	"sync"

	"github.com/relay/relay/internal/core/ports"
)

type MemoryCache struct {
	mu    sync.RWMutex
	items map[string]*ports.ResolvedRedirect
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		items: make(map[string]*ports.ResolvedRedirect),
	}
}

func (c *MemoryCache) Get(ctx context.Context, key string) (*ports.ResolvedRedirect, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, exists := c.items[key]
	return val, exists
}

func (c *MemoryCache) Set(ctx context.Context, key string, val *ports.ResolvedRedirect) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = val
}

func (c *MemoryCache) Delete(ctx context.Context, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}
