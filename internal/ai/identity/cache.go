package identity

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	json "github.com/goccy/go-json"
)

// PermissionCacheConfig configures the three-tier cache.
type PermissionCacheConfig struct {
	L1TTL         time.Duration // In-memory TTL (default 30s)
	L2TTL         time.Duration // Redis TTL (default 5min)
	NegativeTTL   time.Duration // Negative cache TTL (default 10s)
	MaxL1Entries  int           // Max L1 entries per shard (default 10000)
	WarmupOnStart bool          // Pre-populate L1 from L2 on startup
}

func (c *PermissionCacheConfig) withDefaults() *PermissionCacheConfig {
	out := *c
	if out.L1TTL == 0 {
		out.L1TTL = 30 * time.Second
	}
	if out.L2TTL == 0 {
		out.L2TTL = 5 * time.Minute
	}
	if out.NegativeTTL == 0 {
		out.NegativeTTL = 10 * time.Second
	}
	if out.MaxL1Entries == 0 {
		out.MaxL1Entries = 10000
	}
	return &out
}

// CachedPermission holds a cached permission resolution result.
type CachedPermission struct {
	Principal   string    `json:"principal"`
	Groups      []string  `json:"groups"`
	Models      []string  `json:"models"`
	Permissions []string  `json:"permissions"`
	CachedAt    time.Time `json:"cached_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Negative    bool      `json:"negative"`
}

// PermissionConnector is the L3 source of truth.
type PermissionConnector interface {
	Resolve(ctx context.Context, credentialType, credential string) (*CachedPermission, error)
}

// RedisCache wraps Redis operations for L2.
type RedisCache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// CacheMetrics tracks cache hit/miss rates per tier.
type CacheMetrics struct {
	L1Hits   atomic.Int64
	L1Misses atomic.Int64
	L2Hits   atomic.Int64
	L2Misses atomic.Int64
	L3Hits   atomic.Int64
	L3Errors atomic.Int64
	NegHits  atomic.Int64
}

// l1Entry wraps a CachedPermission stored in the sharded sync.Map.
type l1Entry struct {
	perm      *CachedPermission
	expiresAt time.Time
}

const numShards = 16

// PermissionCache provides L1 (sync.Map) + L2 (Redis) + L3 (connector) tiered caching.
type PermissionCache struct {
	config    *PermissionCacheConfig
	l1        [numShards]sync.Map
	l1Counts  [numShards]atomic.Int64
	l2        RedisCache
	connector PermissionConnector
	metrics   CacheMetrics
}

// NewPermissionCache creates a new three-tier permission cache.
// l2 may be nil if Redis is not configured; the cache will skip L2 in that case.
func NewPermissionCache(cfg *PermissionCacheConfig, l2 RedisCache, connector PermissionConnector) *PermissionCache {
	if cfg == nil {
		cfg = &PermissionCacheConfig{}
	}
	resolved := cfg.withDefaults()
	return &PermissionCache{
		config:    resolved,
		l2:        l2,
		connector: connector,
	}
}

// Lookup resolves a permission by falling through L1 -> L2 -> L3.
func (pc *PermissionCache) Lookup(ctx context.Context, credentialType, credential string) (*CachedPermission, error) {
	key := pc.cacheKey(credentialType, credential)
	now := time.Now()

	// L1: check sharded in-memory cache.
	shardIdx := pc.shard(key)
	if val, ok := pc.l1[shardIdx].Load(key); ok {
		entry, entryOk := val.(*l1Entry)
		if entryOk && now.Before(entry.expiresAt) {
			if entry.perm.Negative {
				pc.metrics.NegHits.Add(1)
				return nil, nil
			}
			pc.metrics.L1Hits.Add(1)
			return entry.perm, nil
		}
		// Expired - delete and fall through.
		pc.l1[shardIdx].Delete(key)
		pc.l1Counts[shardIdx].Add(-1)
	}
	pc.metrics.L1Misses.Add(1)

	// L2: check Redis cache (if configured).
	if pc.l2 != nil {
		data, err := pc.l2.Get(ctx, key)
		if err == nil && len(data) > 0 {
			var perm CachedPermission
			if err := json.Unmarshal(data, &perm); err == nil {
				if now.Before(perm.ExpiresAt) {
					if perm.Negative {
						pc.metrics.NegHits.Add(1)
						pc.storeL1(key, &perm, pc.config.NegativeTTL)
						return nil, nil
					}
					pc.metrics.L2Hits.Add(1)
					pc.storeL1(key, &perm, pc.config.L1TTL)
					return &perm, nil
				}
			}
		}
		pc.metrics.L2Misses.Add(1)
	}

	// L3: call connector (source of truth).
	perm, err := pc.connector.Resolve(ctx, credentialType, credential)
	if err != nil {
		pc.metrics.L3Errors.Add(1)
		return nil, fmt.Errorf("identity: L3 resolve failed: %w", err)
	}

	// Negative cache: principal not found.
	if perm == nil {
		neg := &CachedPermission{
			CachedAt:  now,
			ExpiresAt: now.Add(pc.config.NegativeTTL),
			Negative:  true,
		}
		pc.storeL1(key, neg, pc.config.NegativeTTL)
		return nil, nil
	}

	pc.metrics.L3Hits.Add(1)

	// Populate timestamps.
	perm.CachedAt = now
	perm.ExpiresAt = now.Add(pc.config.L2TTL)

	// Store in L1.
	pc.storeL1(key, perm, pc.config.L1TTL)

	// Store in L2 (if configured).
	if pc.l2 != nil {
		data, err := json.Marshal(perm)
		if err == nil {
			// Best-effort: do not fail the lookup if L2 write fails.
			_ = pc.l2.Set(ctx, key, data, pc.config.L2TTL)
		}
	}

	return perm, nil
}

// Invalidate removes a cached permission from all tiers.
func (pc *PermissionCache) Invalidate(ctx context.Context, credentialType, credential string) error {
	key := pc.cacheKey(credentialType, credential)
	shardIdx := pc.shard(key)

	if _, loaded := pc.l1[shardIdx].LoadAndDelete(key); loaded {
		pc.l1Counts[shardIdx].Add(-1)
	}

	if pc.l2 != nil {
		if err := pc.l2.Delete(ctx, key); err != nil {
			return fmt.Errorf("identity: L2 invalidation failed: %w", err)
		}
	}

	return nil
}

// Warmup pre-populates L1 from L2. This is a no-op if L2 is not configured.
func (pc *PermissionCache) Warmup(_ context.Context) error {
	// Warmup requires L2 enumeration which is not supported by the minimal
	// RedisCache interface. This method exists as a hook for implementations
	// that extend RedisCache with key scanning. For now it is a no-op.
	return nil
}

// Stats returns a snapshot of the current cache metrics.
func (pc *PermissionCache) Stats() *CacheMetrics {
	out := &CacheMetrics{}
	out.L1Hits.Store(pc.metrics.L1Hits.Load())
	out.L1Misses.Store(pc.metrics.L1Misses.Load())
	out.L2Hits.Store(pc.metrics.L2Hits.Load())
	out.L2Misses.Store(pc.metrics.L2Misses.Load())
	out.L3Hits.Store(pc.metrics.L3Hits.Load())
	out.L3Errors.Store(pc.metrics.L3Errors.Load())
	out.NegHits.Store(pc.metrics.NegHits.Load())
	return out
}

// shard returns the shard index for a cache key using FNV-1a.
func (pc *PermissionCache) shard(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % numShards)
}

// cacheKey generates a deterministic cache key from credential type and value.
func (pc *PermissionCache) cacheKey(credentialType, credential string) string {
	return "perm:" + credentialType + ":" + credential
}

// storeL1 stores a permission in the appropriate L1 shard, respecting MaxL1Entries.
func (pc *PermissionCache) storeL1(key string, perm *CachedPermission, ttl time.Duration) {
	shardIdx := pc.shard(key)

	// Check capacity before inserting a new key.
	if _, exists := pc.l1[shardIdx].Load(key); !exists {
		count := pc.l1Counts[shardIdx].Load()
		if int(count) >= pc.config.MaxL1Entries {
			// Evict one arbitrary entry to make room.
			pc.l1[shardIdx].Range(func(k, _ any) bool {
				pc.l1[shardIdx].Delete(k)
				pc.l1Counts[shardIdx].Add(-1)
				return false // stop after first deletion
			})
		}
	}

	entry := &l1Entry{
		perm:      perm,
		expiresAt: time.Now().Add(ttl),
	}

	if _, loaded := pc.l1[shardIdx].Swap(key, entry); !loaded {
		pc.l1Counts[shardIdx].Add(1)
	}
}
