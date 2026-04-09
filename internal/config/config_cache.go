// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
)

// ConfigCache provides a multi-layer cache for origin configurations
// Layer 1: LRU in-memory cache (fast, limited size)
// Layer 2: Redis distributed cache (slow, unlimited, shared across instances)
type ConfigCache struct {
	// In-memory LRU cache
	lru      *LRUCache
	lruMu    sync.RWMutex

	// Redis fallback configuration
	redisURL  string
	redisClient *redis.Client
	breaker   *circuitbreaker.CircuitBreaker

	// TTL for cached configs
	ttl time.Duration

	// Metrics
	hits   int64
	misses int64
	mu     sync.RWMutex
}

// CacheEntry represents a cached config with metadata
type CacheEntry struct {
	Config    *Config
	ExpiresAt time.Time
	Hash      string // For validation
}

// LRUCache is a simple LRU cache implementation
type LRUCache struct {
	maxSize int
	items   map[string]*CacheEntry
	order   []string // Track access order for LRU eviction
	mu      sync.RWMutex
}

// NewLRUCache creates a new LRU cache with the specified capacity
func NewLRUCache(maxSize int) *LRUCache {
	return &LRUCache{
		maxSize: maxSize,
		items:   make(map[string]*CacheEntry),
		order:   make([]string, 0, maxSize),
	}
}

// Get retrieves an item from the LRU cache
func (lru *LRUCache) Get(key string) (*CacheEntry, bool) {
	lru.mu.RLock()
	entry, exists := lru.items[key]
	lru.mu.RUnlock()

	if !exists || (entry != nil && time.Now().After(entry.ExpiresAt)) {
		return nil, false
	}

	// Move to end (most recently used)
	lru.mu.Lock()
	// Find and move to end
	for i, k := range lru.order {
		if k == key {
			lru.order = append(lru.order[:i], lru.order[i+1:]...)
			break
		}
	}
	lru.order = append(lru.order, key)
	lru.mu.Unlock()

	return entry, true
}

// Set adds or updates an item in the LRU cache
func (lru *LRUCache) Set(key string, entry *CacheEntry) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	// Remove if exists (to update position)
	if _, exists := lru.items[key]; exists {
		for i, k := range lru.order {
			if k == key {
				lru.order = append(lru.order[:i], lru.order[i+1:]...)
				break
			}
		}
	}

	// Add to end
	lru.items[key] = entry
	lru.order = append(lru.order, key)

	// Evict oldest if over capacity
	if len(lru.order) > lru.maxSize {
		oldest := lru.order[0]
		delete(lru.items, oldest)
		lru.order = lru.order[1:]
	}
}

// Clear removes all entries
func (lru *LRUCache) Clear() {
	lru.mu.Lock()
	defer lru.mu.Unlock()
	lru.items = make(map[string]*CacheEntry)
	lru.order = make([]string, 0, lru.maxSize)
}

// NewConfigCache creates a new config cache
func NewConfigCache(redisURL string, lruSize int, ttl time.Duration) *ConfigCache {
	if ttl == 0 {
		ttl = 5 * time.Minute // Default 5 minute TTL
	}
	if lruSize == 0 {
		lruSize = 100 // Default 100 item LRU
	}

	cache := &ConfigCache{
		lru:      NewLRUCache(lruSize),
		redisURL: redisURL,
		ttl:      ttl,
		breaker: circuitbreaker.New(circuitbreaker.Config{
			Name:             "redis-config-cache",
			FailureThreshold: 5,
			SuccessThreshold: 3,
			Timeout:          10 * time.Second,
		}),
	}

	// Initialize Redis client if URL is provided
	if redisURL != "" {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			slog.Error("failed to parse redis URL", "url", redisURL, "error", err)
		} else {
			cache.redisClient = redis.NewClient(opts)
		}
	}

	return cache
}

// Get retrieves a cached config, checking LRU first, then Redis
func (cc *ConfigCache) Get(ctx context.Context, key string) (*Config, error) {
	// Check LRU cache first
	if entry, found := cc.lru.Get(key); found {
		cc.recordHit()
		slog.Debug("config cache LRU hit", "key", key)
		return entry.Config, nil
	}

	cc.recordMiss()

	// Check Redis fallback if configured
	if cc.redisURL != "" {
		if cfg, err := cc.getFromRedis(ctx, key); err == nil {
			// Cache in LRU for next access
			cc.Set(ctx, key, cfg)
			slog.Debug("config cache Redis hit", "key", key)
			return cfg, nil
		}
		// Redis miss or error is not fatal - continue
	}

	return nil, fmt.Errorf("config not in cache: %s", key)
}

// Set stores a config in the cache (both LRU and Redis)
func (cc *ConfigCache) Set(ctx context.Context, key string, cfg *Config) error {
	entry := &CacheEntry{
		Config:    cfg,
		ExpiresAt: time.Now().Add(cc.ttl),
		Hash:      computeHash(cfg),
	}

	// Store in LRU
	cc.lru.Set(key, entry)

	// Store in Redis if configured
	if cc.redisURL != "" {
		if err := cc.setInRedis(ctx, key, entry); err != nil {
			slog.Warn("failed to store config in Redis", "key", key, "error", err)
			// Not fatal - LRU cache is still available
		}
	}

	return nil
}

// Invalidate removes a config from all caches
func (cc *ConfigCache) Invalidate(ctx context.Context, key string) error {
	// Remove from LRU
	cc.lru.mu.Lock()
	delete(cc.lru.items, key)
	for i, k := range cc.lru.order {
		if k == key {
			cc.lru.order = append(cc.lru.order[:i], cc.lru.order[i+1:]...)
			break
		}
	}
	cc.lru.mu.Unlock()

	// Remove from Redis if configured
	if cc.redisURL != "" {
		if err := cc.removeFromRedis(ctx, key); err != nil {
			slog.Warn("failed to remove config from Redis", "key", key, "error", err)
		}
	}

	return nil
}

// getFromRedis retrieves a config from Redis (circuit breaker protected)
func (cc *ConfigCache) getFromRedis(ctx context.Context, key string) (*Config, error) {
	if cc.redisClient == nil {
		return nil, fmt.Errorf("redis not configured")
	}

	var cfg *Config
	err := cc.breaker.Call(func() error {
		// Get value from Redis
		value, err := cc.redisClient.Get(ctx, key).Bytes()
		if err != nil {
			if err == redis.Nil {
				return fmt.Errorf("key not found in redis")
			}
			return err
		}

		// Unmarshal JSON into config
		if err := json.Unmarshal(value, &cfg); err != nil {
			return fmt.Errorf("failed to unmarshal config from redis: %w", err)
		}

		return nil
	})

	if err == circuitbreaker.ErrCircuitOpen {
		slog.Warn("Redis circuit breaker open for config cache", "key", key)
		return nil, err
	}

	return cfg, err
}

// setInRedis stores a config in Redis (circuit breaker protected)
func (cc *ConfigCache) setInRedis(ctx context.Context, key string, entry *CacheEntry) error {
	if cc.redisClient == nil {
		return fmt.Errorf("redis not configured")
	}

	return cc.breaker.Call(func() error {
		// Marshal config to JSON
		data, err := json.Marshal(entry.Config)
		if err != nil {
			return fmt.Errorf("failed to marshal config for redis: %w", err)
		}

		// Set in Redis with TTL
		if err := cc.redisClient.Set(ctx, key, data, cc.ttl).Err(); err != nil {
			return fmt.Errorf("failed to set config in redis: %w", err)
		}

		return nil
	})
}

// removeFromRedis removes a config from Redis (circuit breaker protected)
func (cc *ConfigCache) removeFromRedis(ctx context.Context, key string) error {
	if cc.redisClient == nil {
		return fmt.Errorf("redis not configured")
	}

	return cc.breaker.Call(func() error {
		if err := cc.redisClient.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("failed to delete config from redis: %w", err)
		}
		return nil
	})
}

// Clear clears all caches
func (cc *ConfigCache) Clear() error {
	cc.lru.Clear()

	if cc.redisURL != "" {
		// TODO: Clear Redis cache when implemented
	}

	return nil
}

// Stats returns cache statistics
func (cc *ConfigCache) Stats() map[string]interface{} {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	total := cc.hits + cc.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(cc.hits) / float64(total) * 100
	}

	cc.lru.mu.RLock()
	lruSize := len(cc.lru.items)
	cc.lru.mu.RUnlock()

	return map[string]interface{}{
		"hits":      cc.hits,
		"misses":    cc.misses,
		"total":     total,
		"hit_rate":  hitRate,
		"lru_size":  lruSize,
		"lru_max":   cc.lru.maxSize,
	}
}

// Helper methods

func (cc *ConfigCache) recordHit() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.hits++
}

func (cc *ConfigCache) recordMiss() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.misses++
}

// computeHash computes a SHA256 hash of a config for validation
func computeHash(cfg *Config) string {
	data, _ := json.Marshal(cfg)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
