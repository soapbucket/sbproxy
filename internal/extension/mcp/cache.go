// cache.go implements a TTL-based cache for MCP tool execution results.
package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ToolResultCache caches tool execution results with TTL.
type ToolResultCache struct {
	entries    map[string]*cacheEntry
	mu         sync.RWMutex
	maxEntries int
	defaultTTL time.Duration
}

type cacheEntry struct {
	result    *ToolResult
	expiresAt time.Time
}

// NewToolResultCache creates a new tool result cache.
func NewToolResultCache(config *ToolCacheConfig) *ToolResultCache {
	if config == nil {
		return nil
	}

	defaultTTL := 2 * time.Minute
	if config.DefaultTTL.Duration > 0 {
		defaultTTL = config.DefaultTTL.Duration
	}

	maxEntries := 1000
	if config.MaxEntries > 0 {
		maxEntries = config.MaxEntries
	}

	cache := &ToolResultCache{
		entries:    make(map[string]*cacheEntry),
		maxEntries: maxEntries,
		defaultTTL: defaultTTL,
	}

	// Start background eviction
	go cache.evictLoop()

	return cache
}

// Get returns a cached result if available and not expired.
func (c *ToolResultCache) Get(key string) (*ToolResult, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		// Expired - remove lazily
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}

	return entry.result, true
}

// Put stores a result in the cache with the specified TTL.
func (c *ToolResultCache) Put(key string, result *ToolResult, ttl time.Duration) {
	if c == nil {
		return
	}

	if ttl <= 0 {
		ttl = c.defaultTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest entries if at capacity
	if len(c.entries) >= c.maxEntries {
		c.evictExpired()
		// If still at capacity after evicting expired, remove one entry
		if len(c.entries) >= c.maxEntries {
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}

	c.entries[key] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}
}

// Delete removes a specific entry from the cache.
func (c *ToolResultCache) Delete(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// Clear removes all entries from the cache.
func (c *ToolResultCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[string]*cacheEntry)
	c.mu.Unlock()
}

// Size returns the number of entries in the cache.
func (c *ToolResultCache) Size() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *ToolResultCache) evictExpired() {
	now := time.Now()
	for k, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, k)
		}
	}
}

func (c *ToolResultCache) evictLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		c.evictExpired()
		c.mu.Unlock()
	}
}

// BuildCacheKey generates a cache key for a tool call based on tool config.
func BuildCacheKey(ctx context.Context, toolName string, args map[string]interface{}, cacheConfig *ToolCacheEntry) string {
	scope := "shared"
	if cacheConfig != nil && cacheConfig.Scope != "" {
		scope = cacheConfig.Scope
	}

	// Base key from tool name and arguments
	argsHash := hashArgs(args)
	key := fmt.Sprintf("mcp:tool:%s:%s", toolName, argsHash)

	// Add identity scope
	switch scope {
	case "per_user":
		roles, _ := extractIdentity(ctx)
		if len(roles) > 0 {
			key = fmt.Sprintf("%s:user:%x", key, sha256.Sum256([]byte(fmt.Sprint(roles))))
		}
	case "per_key":
		_, keyID := extractIdentity(ctx)
		if keyID != "" {
			key = fmt.Sprintf("%s:key:%s", key, keyID)
		}
	}

	return key
}

func hashArgs(args map[string]interface{}) string {
	if len(args) == 0 {
		return "noargs"
	}
	data, err := json.Marshal(args)
	if err != nil {
		return "err"
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:8])
}
