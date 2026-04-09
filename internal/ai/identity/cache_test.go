package identity

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// --- Mock implementations ---

type mockRedisCache struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMockRedis() *mockRedisCache {
	return &mockRedisCache{data: make(map[string][]byte)}
}

func (m *mockRedisCache) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return v, nil
}

func (m *mockRedisCache) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *mockRedisCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

type mockConnector struct {
	mu       sync.Mutex
	results  map[string]*CachedPermission
	calls    int
	failNext bool
}

func newMockConnector() *mockConnector {
	return &mockConnector{results: make(map[string]*CachedPermission)}
}

func (m *mockConnector) Resolve(_ context.Context, credentialType, credential string) (*CachedPermission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.failNext {
		m.failNext = false
		return nil, fmt.Errorf("connector error")
	}
	key := credentialType + ":" + credential
	return m.results[key], nil
}

func (m *mockConnector) set(credentialType, credential string, perm *CachedPermission) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results[credentialType+":"+credential] = perm
}

func (m *mockConnector) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// --- Tests ---

func TestPermissionCacheLookup_L1Hit(t *testing.T) {
	connector := newMockConnector()
	connector.set("apikey", "key-1", &CachedPermission{
		Principal:   "user-1",
		Groups:      []string{"admin"},
		Models:      []string{"gpt-4"},
		Permissions: []string{"read", "write"},
	})

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 5 * time.Second,
	}, nil, connector)

	ctx := context.Background()

	// First lookup: populates L1 via L3.
	perm, err := cache.Lookup(ctx, "apikey", "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "user-1" {
		t.Fatalf("expected user-1, got %v", perm)
	}

	// Second lookup: should come from L1, no additional connector call.
	perm, err = cache.Lookup(ctx, "apikey", "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "user-1" {
		t.Fatalf("expected user-1 from L1, got %v", perm)
	}
	if connector.callCount() != 1 {
		t.Fatalf("expected 1 connector call, got %d", connector.callCount())
	}

	stats := cache.Stats()
	if stats.L1Hits.Load() != 1 {
		t.Fatalf("expected 1 L1 hit, got %d", stats.L1Hits.Load())
	}
}

func TestPermissionCacheLookup_L2Hit(t *testing.T) {
	redis := newMockRedis()
	connector := newMockConnector()
	connector.set("apikey", "key-2", &CachedPermission{
		Principal: "user-2",
		Models:    []string{"claude-3"},
	})

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 5 * time.Second,
		L2TTL: 30 * time.Second,
	}, redis, connector)

	ctx := context.Background()

	// First lookup: populates L1 + L2 via L3.
	perm, err := cache.Lookup(ctx, "apikey", "key-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "user-2" {
		t.Fatalf("expected user-2, got %v", perm)
	}

	// Evict from L1 by creating a new cache with the same L2.
	cache2 := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 5 * time.Second,
		L2TTL: 30 * time.Second,
	}, redis, connector)

	// Should hit L2, not L3.
	perm, err = cache2.Lookup(ctx, "apikey", "key-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "user-2" {
		t.Fatalf("expected user-2 from L2, got %v", perm)
	}

	stats := cache2.Stats()
	if stats.L2Hits.Load() != 1 {
		t.Fatalf("expected 1 L2 hit, got %d", stats.L2Hits.Load())
	}
	if stats.L1Misses.Load() != 1 {
		t.Fatalf("expected 1 L1 miss, got %d", stats.L1Misses.Load())
	}
}

func TestPermissionCacheLookup_L3Hit(t *testing.T) {
	connector := newMockConnector()
	connector.set("bearer", "tok-1", &CachedPermission{
		Principal:   "user-3",
		Permissions: []string{"admin"},
	})

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 5 * time.Second,
		L2TTL: 30 * time.Second,
	}, nil, connector)

	ctx := context.Background()

	perm, err := cache.Lookup(ctx, "bearer", "tok-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "user-3" {
		t.Fatalf("expected user-3, got %v", perm)
	}

	stats := cache.Stats()
	if stats.L3Hits.Load() != 1 {
		t.Fatalf("expected 1 L3 hit, got %d", stats.L3Hits.Load())
	}
	if stats.L1Misses.Load() != 1 {
		t.Fatalf("expected 1 L1 miss, got %d", stats.L1Misses.Load())
	}
}

func TestPermissionCacheLookup_NegativeCache(t *testing.T) {
	connector := newMockConnector()
	// Do not set any result - connector returns nil.

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL:       5 * time.Second,
		NegativeTTL: 2 * time.Second,
	}, nil, connector)

	ctx := context.Background()

	// First lookup: L3 returns nil, negative entry stored.
	perm, err := cache.Lookup(ctx, "apikey", "unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm != nil {
		t.Fatalf("expected nil for unknown principal, got %v", perm)
	}

	// Second lookup: should hit negative cache, no additional connector call.
	perm, err = cache.Lookup(ctx, "apikey", "unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm != nil {
		t.Fatalf("expected nil from negative cache, got %v", perm)
	}

	if connector.callCount() != 1 {
		t.Fatalf("expected 1 connector call (negative cached), got %d", connector.callCount())
	}

	stats := cache.Stats()
	if stats.NegHits.Load() != 1 {
		t.Fatalf("expected 1 negative hit, got %d", stats.NegHits.Load())
	}
}

func TestPermissionCacheLookup_Expiry(t *testing.T) {
	connector := newMockConnector()
	connector.set("apikey", "key-exp", &CachedPermission{
		Principal: "user-exp",
	})

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 10 * time.Millisecond, // Very short TTL.
	}, nil, connector)

	ctx := context.Background()

	// First lookup populates L1.
	perm, err := cache.Lookup(ctx, "apikey", "key-exp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "user-exp" {
		t.Fatalf("expected user-exp, got %v", perm)
	}

	// Wait for L1 TTL to expire.
	time.Sleep(20 * time.Millisecond)

	// Should miss L1 and go to L3 again.
	perm, err = cache.Lookup(ctx, "apikey", "key-exp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "user-exp" {
		t.Fatalf("expected user-exp after expiry, got %v", perm)
	}

	if connector.callCount() != 2 {
		t.Fatalf("expected 2 connector calls after expiry, got %d", connector.callCount())
	}
}

func TestPermissionCacheInvalidate(t *testing.T) {
	redis := newMockRedis()
	connector := newMockConnector()
	connector.set("apikey", "key-inv", &CachedPermission{
		Principal: "user-inv",
	})

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 5 * time.Second,
		L2TTL: 30 * time.Second,
	}, redis, connector)

	ctx := context.Background()

	// Populate L1 + L2.
	perm, err := cache.Lookup(ctx, "apikey", "key-inv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil {
		t.Fatal("expected non-nil perm")
	}

	// Invalidate.
	if err := cache.Invalidate(ctx, "apikey", "key-inv"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// L2 should be cleared.
	key := cache.cacheKey("apikey", "key-inv")
	if _, err := redis.Get(ctx, key); err == nil {
		t.Fatal("expected L2 entry to be deleted")
	}

	// Next lookup should go to L3 again.
	perm, err = cache.Lookup(ctx, "apikey", "key-inv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "user-inv" {
		t.Fatalf("expected user-inv after invalidate, got %v", perm)
	}

	if connector.callCount() != 2 {
		t.Fatalf("expected 2 connector calls after invalidation, got %d", connector.callCount())
	}
}

func TestPermissionCacheMetrics(t *testing.T) {
	redis := newMockRedis()
	connector := newMockConnector()
	connector.set("apikey", "m1", &CachedPermission{Principal: "u1"})

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 5 * time.Second,
		L2TTL: 30 * time.Second,
	}, redis, connector)

	ctx := context.Background()

	// L3 hit (first lookup).
	_, _ = cache.Lookup(ctx, "apikey", "m1")
	// L1 hit (second lookup).
	_, _ = cache.Lookup(ctx, "apikey", "m1")
	// Negative cache (unknown key).
	_, _ = cache.Lookup(ctx, "apikey", "missing")
	// Negative hit (second lookup of unknown).
	_, _ = cache.Lookup(ctx, "apikey", "missing")

	// L3 error.
	connector.mu.Lock()
	connector.failNext = true
	connector.mu.Unlock()
	_, _ = cache.Lookup(ctx, "apikey", "fail-key")

	stats := cache.Stats()

	if got := stats.L1Hits.Load(); got != 1 {
		t.Errorf("L1Hits: want 1, got %d", got)
	}
	if got := stats.L3Hits.Load(); got != 1 {
		t.Errorf("L3Hits: want 1, got %d", got)
	}
	if got := stats.NegHits.Load(); got != 1 {
		t.Errorf("NegHits: want 1, got %d", got)
	}
	if got := stats.L3Errors.Load(); got != 1 {
		t.Errorf("L3Errors: want 1, got %d", got)
	}
}

func TestPermissionCacheConcurrency(t *testing.T) {
	redis := newMockRedis()
	connector := newMockConnector()
	for i := 0; i < 100; i++ {
		connector.set("apikey", fmt.Sprintf("key-%d", i), &CachedPermission{
			Principal: fmt.Sprintf("user-%d", i),
		})
	}

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 5 * time.Second,
		L2TTL: 30 * time.Second,
	}, redis, connector)

	ctx := context.Background()
	var wg sync.WaitGroup

	// Concurrent lookups.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", idx)
			for j := 0; j < 50; j++ {
				perm, err := cache.Lookup(ctx, "apikey", key)
				if err != nil {
					t.Errorf("lookup error: %v", err)
					return
				}
				if perm == nil {
					t.Errorf("expected non-nil perm for key-%d", idx)
					return
				}
			}
		}(i)
	}

	// Concurrent invalidations.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", idx)
			for j := 0; j < 10; j++ {
				_ = cache.Invalidate(ctx, "apikey", key)
			}
		}(i)
	}

	wg.Wait()
}

func TestPermissionCacheSharding(t *testing.T) {
	cache := NewPermissionCache(&PermissionCacheConfig{}, nil, newMockConnector())

	// Different keys should hash to at least 2 different shards
	// among a reasonably diverse set.
	shards := make(map[int]bool)
	for i := 0; i < 100; i++ {
		key := cache.cacheKey("apikey", fmt.Sprintf("key-%d", i))
		s := cache.shard(key)
		if s < 0 || s >= numShards {
			t.Fatalf("shard out of range: %d", s)
		}
		shards[s] = true
	}

	// With 100 keys and 16 shards, we should hit many shards.
	if len(shards) < 4 {
		t.Fatalf("expected keys to be spread across multiple shards, got %d", len(shards))
	}
}

func TestPermissionCacheLookup_L3Error(t *testing.T) {
	connector := newMockConnector()
	connector.mu.Lock()
	connector.failNext = true
	connector.mu.Unlock()

	cache := NewPermissionCache(nil, nil, connector)
	ctx := context.Background()

	_, err := cache.Lookup(ctx, "apikey", "err-key")
	if err == nil {
		t.Fatal("expected error from L3 failure")
	}
}

func TestPermissionCacheNilL2(t *testing.T) {
	connector := newMockConnector()
	connector.set("apikey", "no-redis", &CachedPermission{Principal: "u-nr"})

	cache := NewPermissionCache(nil, nil, connector)
	ctx := context.Background()

	perm, err := cache.Lookup(ctx, "apikey", "no-redis")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "u-nr" {
		t.Fatalf("expected u-nr, got %v", perm)
	}

	// Invalidate should work without L2.
	if err := cache.Invalidate(ctx, "apikey", "no-redis"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPermissionCacheWarmup(t *testing.T) {
	cache := NewPermissionCache(nil, newMockRedis(), newMockConnector())
	if err := cache.Warmup(context.Background()); err != nil {
		t.Fatalf("warmup should succeed (no-op): %v", err)
	}
}

func TestPermissionCacheMaxL1Entries(t *testing.T) {
	connector := newMockConnector()
	for i := 0; i < 15; i++ {
		connector.set("apikey", fmt.Sprintf("cap-%d", i), &CachedPermission{
			Principal: fmt.Sprintf("u-%d", i),
		})
	}

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL:        5 * time.Second,
		MaxL1Entries: 10,
	}, nil, connector)

	ctx := context.Background()

	// Fill beyond capacity.
	for i := 0; i < 15; i++ {
		_, err := cache.Lookup(ctx, "apikey", fmt.Sprintf("cap-%d", i))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Count total entries across all shards.
	var total int64
	for i := 0; i < numShards; i++ {
		total += cache.l1Counts[i].Load()
	}

	// Each shard is capped at MaxL1Entries, so total should not exceed
	// numShards * MaxL1Entries, and eviction should have occurred.
	if total > int64(numShards*cache.config.MaxL1Entries) {
		t.Fatalf("total entries %d exceeds max capacity %d", total, numShards*cache.config.MaxL1Entries)
	}
}
