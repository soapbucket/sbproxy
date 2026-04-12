package identity

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func BenchmarkPermissionCache_L1Hit(b *testing.B) {
	connector := newMockConnector()
	connector.set("apikey", "bench-l1", &CachedPermission{
		Principal:   "user-bench",
		Groups:      []string{"admin"},
		Models:      []string{"gpt-4", "claude-3"},
		Permissions: []string{"read", "write", "admin"},
	})

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 1 * time.Hour,
	}, nil, connector)

	ctx := context.Background()

	// Pre-populate L1.
	_, _ = cache.Lookup(ctx, "apikey", "bench-l1")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Lookup(ctx, "apikey", "bench-l1")
	}
}

func BenchmarkPermissionCache_L2Hit(b *testing.B) {
	redis := newMockRedis()
	connector := newMockConnector()
	connector.set("apikey", "bench-l2", &CachedPermission{
		Principal:   "user-bench-l2",
		Groups:      []string{"eng"},
		Models:      []string{"claude-3"},
		Permissions: []string{"read"},
	})

	// Populate L2 via a temporary cache.
	temp := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 1 * time.Hour,
		L2TTL: 1 * time.Hour,
	}, redis, connector)
	ctx := context.Background()
	_, _ = temp.Lookup(ctx, "apikey", "bench-l2")

	// Create a fresh cache sharing L2 but with empty L1.
	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 1 * time.Nanosecond, // Expire L1 immediately to force L2 reads.
		L2TTL: 1 * time.Hour,
	}, redis, connector)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Lookup(ctx, "apikey", "bench-l2")
	}
}

func BenchmarkPermissionCache_NegativeHit(b *testing.B) {
	connector := newMockConnector()

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL:       1 * time.Hour,
		NegativeTTL: 1 * time.Hour,
	}, nil, connector)

	ctx := context.Background()

	// Pre-populate negative entry.
	_, _ = cache.Lookup(ctx, "apikey", "nonexistent")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Lookup(ctx, "apikey", "nonexistent")
	}
}

func BenchmarkPermissionCache_Lookup_Parallel(b *testing.B) {
	redis := newMockRedis()
	connector := newMockConnector()
	for i := 0; i < 100; i++ {
		connector.set("apikey", fmt.Sprintf("par-%d", i), &CachedPermission{
			Principal: fmt.Sprintf("user-%d", i),
			Models:    []string{"gpt-4"},
		})
	}

	cache := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 1 * time.Hour,
		L2TTL: 1 * time.Hour,
	}, redis, connector)

	ctx := context.Background()

	// Pre-populate.
	for i := 0; i < 100; i++ {
		_, _ = cache.Lookup(ctx, "apikey", fmt.Sprintf("par-%d", i))
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("par-%d", i%100)
			_, _ = cache.Lookup(ctx, "apikey", key)
			i++
		}
	})
}
