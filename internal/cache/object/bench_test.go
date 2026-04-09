package objectcache

import (
	"fmt"
	"testing"
	"time"
)

// newBenchCache creates an ObjectCache sized for benchmarking. The cleaner
// goroutine uses a long interval so it does not interfere with measurements.
func newBenchCache(b *testing.B, maxObjects int) *ObjectCache {
	b.Helper()
	cache, err := NewObjectCache(5*time.Minute, 10*time.Minute, maxObjects, 0)
	if err != nil {
		b.Fatalf("failed to create cache: %v", err)
	}
	b.Cleanup(func() { cache.Close() })
	return cache
}

// populateCache fills the cache with n entries keyed "key-0" through "key-(n-1)".
func populateCache(cache *ObjectCache, n int) {
	for i := 0; i < n; i++ {
		cache.Put(fmt.Sprintf("key-%d", i), "value")
	}
}

// --- Get (cache hit) ---

// BenchmarkGet_Hit benchmarks reading an existing key from caches of various sizes.
func BenchmarkGet_Hit(b *testing.B) {
	sizes := []int{100, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			cache := newBenchCache(b, 0)
			populateCache(cache, size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := fmt.Sprintf("key-%d", i%size)
				cache.Get(key)
			}
		})
	}
}

// --- Get (cache miss) ---

// BenchmarkGet_Miss benchmarks a lookup for keys that do not exist.
func BenchmarkGet_Miss(b *testing.B) {
	sizes := []int{100, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			cache := newBenchCache(b, 0)
			populateCache(cache, size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// These keys were never inserted.
				key := fmt.Sprintf("miss-%d", i%size)
				cache.Get(key)
			}
		})
	}
}

// --- Set (Put) ---

// BenchmarkSet benchmarks inserting/updating entries in caches of various sizes.
func BenchmarkSet(b *testing.B) {
	sizes := []int{100, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			cache := newBenchCache(b, 0)
			populateCache(cache, size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Mix of updates (existing keys) and inserts (new keys).
				key := fmt.Sprintf("key-%d", i%(size*2))
				cache.Put(key, "new-value")
			}
		})
	}
}

// --- Set with eviction ---

// BenchmarkSet_WithEviction benchmarks Put when the cache is at capacity
// and every insert triggers an LRU eviction.
func BenchmarkSet_WithEviction(b *testing.B) {
	sizes := []int{100, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			cache := newBenchCache(b, size)
			populateCache(cache, size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Always use new keys to force eviction.
				key := fmt.Sprintf("evict-%d", i)
				cache.Put(key, "value")
			}
		})
	}
}

// --- Delete ---

// BenchmarkDelete benchmarks deleting existing keys from caches of various sizes.
func BenchmarkDelete(b *testing.B) {
	sizes := []int{100, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			cache := newBenchCache(b, 0)

			// Pre-populate and prepare keys. Re-populate before each
			// sub-benchmark iteration would skew results, so we delete
			// from a rotating set and re-insert after deleting.
			populateCache(cache, size)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := fmt.Sprintf("key-%d", i%size)
				cache.Delete(key)
				// Re-insert so the next iteration has something to delete.
				cache.Put(key, "value")
			}
		})
	}
}

// --- PutWithExpires ---

// BenchmarkPutWithExpires benchmarks inserting entries with a custom TTL.
func BenchmarkPutWithExpires(b *testing.B) {
	b.ReportAllocs()
	cache := newBenchCache(b, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i%1000)
		cache.PutWithExpires(key, "value", 30*time.Second)
	}
}

// --- Increment ---

// BenchmarkIncrement benchmarks the atomic increment operation used by
// the rate limiter's in-memory cache path.
func BenchmarkIncrement(b *testing.B) {
	b.ReportAllocs()
	cache := newBenchCache(b, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Increment("counter", 1)
	}
}

// --- Concurrent Get/Put ---

// BenchmarkConcurrent_GetPut benchmarks mixed read/write workloads across
// multiple goroutines.
func BenchmarkConcurrent_GetPut(b *testing.B) {
	sizes := []int{100, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			cache := newBenchCache(b, 0)
			populateCache(cache, size)

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					key := fmt.Sprintf("key-%d", i%size)
					if i%2 == 0 {
						cache.Get(key)
					} else {
						cache.Put(key, "value")
					}
					i++
				}
			})
		})
	}
}
