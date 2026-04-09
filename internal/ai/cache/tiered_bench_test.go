package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func BenchmarkTieredCache_L1Hit(b *testing.B) {
	tc := NewTieredCache(TieredCacheConfig{
		Enabled:      true,
		L1MaxEntries: 10000,
		L1TTL:        5 * time.Minute,
	}, nil, nil)

	resp := &CachedResponse{
		Key:       "bench-key",
		Response:  json.RawMessage(`{"choices":[{"message":{"content":"Hello!"}}]}`),
		Model:     "gpt-4o",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	tc.l1.Set("bench-key", resp)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tc.Lookup(ctx, "bench-key", nil)
	}
}

func BenchmarkTieredCache_Store(b *testing.B) {
	tc := NewTieredCache(TieredCacheConfig{
		Enabled:      true,
		L1MaxEntries: 10000,
		L1TTL:        5 * time.Minute,
	}, nil, nil)

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench-store-%d", i)
		resp := &CachedResponse{
			Key:       key,
			Response:  json.RawMessage(`{"choices":[{"message":{"content":"Hello!"}}]}`),
			Model:     "gpt-4o",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		tc.Store(ctx, key, resp, nil)
	}
}

func BenchmarkBuildCacheKey(b *testing.B) {
	msgs := json.RawMessage(`[{"role":"user","content":"What is the meaning of life?"}]`)
	temp := 0.7

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		BuildCacheKey("gpt-4o", msgs, &temp, 1000)
	}
}

func BenchmarkCoalescer(b *testing.B) {
	c := NewCoalescer(100 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("coal-%d", i)
		c.Start(key)
		c.Complete(key, &CachedResponse{
			Key:      key,
			Response: json.RawMessage(`{}`),
		}, nil)
	}
}

func BenchmarkL1Cache_GetSet(b *testing.B) {
	c := NewL1Cache(10000)

	// Pre-populate.
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("bench-%d", i)
		c.Set(key, &CachedResponse{
			Key:       key,
			Response:  json.RawMessage(`{"i":1}`),
			Model:     "gpt-4o",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench-%d", i%1000)
		if i%2 == 0 {
			c.Get(key)
		} else {
			c.Set(key, &CachedResponse{
				Key:       key,
				Response:  json.RawMessage(`{"i":1}`),
				Model:     "gpt-4o",
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(5 * time.Minute),
			})
		}
	}
}
