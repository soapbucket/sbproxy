package ratelimit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// newBenchCache creates a memory-backed cacher for benchmark isolation.
func newBenchCache(b *testing.B) cacher.Cacher {
	b.Helper()
	cache, err := cacher.NewCacher(cacher.Settings{
		Driver:     "memory",
		MaxObjects: 100000,
	})
	if err != nil {
		b.Fatalf("failed to create cache: %v", err)
	}
	b.Cleanup(func() { cache.Close() })
	return cache
}

// BenchmarkSlidingWindow_Allow benchmarks the sliding window Allow() method
// with different window durations to measure the cost of the weighted
// interpolation algorithm.
func BenchmarkSlidingWindow_Allow(b *testing.B) {
	windows := []struct {
		name   string
		window time.Duration
	}{
		{"1s", time.Second},
		{"60s", 60 * time.Second},
	}

	for _, w := range windows {
		b.Run(w.name, func(b *testing.B) {
			b.ReportAllocs()
			cache := newBenchCache(b)
			rl := NewDistributedRateLimiter(cache, "bench")
			ctx := context.Background()

			// Use a high limit so requests are never denied during the benchmark.
			limit := 1_000_000

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rl.Allow(ctx, "bench-key", limit, w.window)
			}
		})
	}
}

// BenchmarkSlidingWindow_AllowN benchmarks the cost-based AllowN variant.
func BenchmarkSlidingWindow_AllowN(b *testing.B) {
	b.ReportAllocs()
	cache := newBenchCache(b)
	rl := NewDistributedRateLimiter(cache, "bench")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.AllowN(ctx, "bench-key", 5, 1_000_000, time.Second)
	}
}

// BenchmarkSlidingWindow_Allow_Denied benchmarks the denied path, where the
// rate limiter must compute the retry-after duration.
func BenchmarkSlidingWindow_Allow_Denied(b *testing.B) {
	b.ReportAllocs()
	cache := newBenchCache(b)
	rl := NewDistributedRateLimiter(cache, "bench")
	ctx := context.Background()

	// Exhaust the limit first.
	limit := 10
	for i := 0; i < limit; i++ {
		rl.Allow(ctx, "denied-key", limit, 60*time.Second)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(ctx, "denied-key", limit, 60*time.Second)
	}
}

// BenchmarkSlidingWindow_Allow_Parallel benchmarks concurrent access to the
// sliding window rate limiter from multiple goroutines.
func BenchmarkSlidingWindow_Allow_Parallel(b *testing.B) {
	b.ReportAllocs()
	cache := newBenchCache(b)
	rl := NewDistributedRateLimiter(cache, "bench")
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.Allow(ctx, "parallel-key", 1_000_000, time.Second)
		}
	})
}

// BenchmarkSlidingWindow_Allow_MultipleKeys benchmarks the rate limiter when
// each iteration uses a different key, stressing the cache write path.
func BenchmarkSlidingWindow_Allow_MultipleKeys(b *testing.B) {
	b.ReportAllocs()
	cache := newBenchCache(b)
	rl := NewDistributedRateLimiter(cache, "bench")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("user-%d", i%1000)
		rl.Allow(ctx, key, 1_000_000, time.Second)
	}
}

// BenchmarkFixedWindow_Allow benchmarks the fixed window Allow() method
// with different window durations.
func BenchmarkFixedWindow_Allow(b *testing.B) {
	windows := []struct {
		name   string
		window time.Duration
	}{
		{"1s", time.Second},
		{"60s", 60 * time.Second},
	}

	for _, w := range windows {
		b.Run(w.name, func(b *testing.B) {
			b.ReportAllocs()
			cache := newBenchCache(b)
			fw := NewFixedWindow(cache, "bench")
			ctx := context.Background()

			limit := 1_000_000

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fw.Allow(ctx, "bench-key", limit, w.window)
			}
		})
	}
}

// BenchmarkFixedWindow_Allow_Parallel benchmarks concurrent access to the
// fixed window rate limiter.
func BenchmarkFixedWindow_Allow_Parallel(b *testing.B) {
	b.ReportAllocs()
	cache := newBenchCache(b)
	fw := NewFixedWindow(cache, "bench")
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			fw.Allow(ctx, "parallel-key", 1_000_000, time.Second)
		}
	})
}

// BenchmarkTokenBucket_Allow benchmarks the token bucket Allow() method.
func BenchmarkTokenBucket_Allow(b *testing.B) {
	b.ReportAllocs()
	cache := newBenchCache(b)
	tb := NewTokenBucket(cache, "bench", 1_000_000, 100.0)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.Allow(ctx, "bench-key", 1_000_000, time.Second)
	}
}

// BenchmarkLeakyBucket_Allow benchmarks the leaky bucket Allow() method.
func BenchmarkLeakyBucket_Allow(b *testing.B) {
	b.ReportAllocs()
	cache := newBenchCache(b)
	lb := NewLeakyBucket(cache, "bench", 1_000_000, 100.0)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lb.Allow(ctx, "bench-key", 1_000_000, time.Second)
	}
}
