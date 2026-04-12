package lru

import (
	"fmt"
	"sync"
	"testing"
)

// TestGet_Set_Eviction_Lifecycle verifies the full lifecycle of cache operations:
// insert, retrieve, evict, and verify eviction ordering.
func TestGet_Set_Eviction_Lifecycle(t *testing.T) {
	evicted := make([]string, 0)
	c := New[string, int](3, func(k string, v int) {
		evicted = append(evicted, k)
	})

	// Fill cache to capacity.
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	if c.Len() != 3 {
		t.Fatalf("expected len 3, got %d", c.Len())
	}

	// Access "a" to make it MRU. LRU order: b, c, a.
	v, ok := c.Get("a")
	if !ok || v != 1 {
		t.Fatalf("expected (1, true), got (%d, %v)", v, ok)
	}

	// Insert "d" - should evict "b" (LRU).
	c.Put("d", 4)
	if len(evicted) != 1 || evicted[0] != "b" {
		t.Fatalf("expected eviction of 'b', got %v", evicted)
	}

	// "b" should be gone.
	_, ok = c.Get("b")
	if ok {
		t.Fatal("expected 'b' to be evicted")
	}

	// "a", "c", "d" should remain.
	for _, key := range []string{"a", "c", "d"} {
		_, ok = c.Get(key)
		if !ok {
			t.Fatalf("expected %q to still exist", key)
		}
	}
}

// TestPut_Update_DoesNotEvict verifies that updating an existing key does not
// trigger eviction or change cache size.
func TestPut_Update_DoesNotEvict(t *testing.T) {
	evictCount := 0
	c := New[string, int](2, func(k string, v int) {
		evictCount++
	})

	c.Put("a", 1)
	c.Put("b", 2)

	// Update "a" - should not evict.
	c.Put("a", 100)

	if evictCount != 0 {
		t.Fatalf("expected 0 evictions on update, got %d", evictCount)
	}
	if c.Len() != 2 {
		t.Fatalf("expected len 2, got %d", c.Len())
	}

	v, ok := c.Get("a")
	if !ok || v != 100 {
		t.Fatalf("expected updated value 100, got %d", v)
	}
}

// TestPut_Update_PromotesToMRU verifies that updating a key promotes it to
// the most-recently-used position.
func TestPut_Update_PromotesToMRU(t *testing.T) {
	evicted := make([]string, 0)
	c := New[string, int](3, func(k string, v int) {
		evicted = append(evicted, k)
	})

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	// Update "a" to promote it to MRU. LRU order: b, c, a.
	c.Put("a", 10)

	// Insert "d" - should evict "b" (LRU), not "a".
	c.Put("d", 4)

	if len(evicted) != 1 || evicted[0] != "b" {
		t.Fatalf("expected eviction of 'b' (not updated 'a'), got %v", evicted)
	}
}

// TestDelete_ReturnsCorrectly verifies that Delete returns true for existing
// keys and false for missing ones.
func TestDelete_ReturnsCorrectly(t *testing.T) {
	c := New[string, int](5, nil)
	c.Put("a", 1)
	c.Put("b", 2)

	tests := []struct {
		key  string
		want bool
	}{
		{"a", true},
		{"b", true},
		{"c", false},
		{"a", false}, // already deleted
	}

	for _, tc := range tests {
		got := c.Delete(tc.key)
		if got != tc.want {
			t.Errorf("Delete(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

// TestDelete_DoesNotAffectOtherEntries verifies that deleting one entry
// leaves others accessible.
func TestDelete_DoesNotAffectOtherEntries(t *testing.T) {
	c := New[string, int](5, nil)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	c.Delete("b")

	for _, key := range []string{"a", "c"} {
		_, ok := c.Get(key)
		if !ok {
			t.Errorf("expected %q to still exist after deleting 'b'", key)
		}
	}
}

// TestClear_ThenReuse verifies that the cache can be reused after Clear().
func TestClear_ThenReuse(t *testing.T) {
	c := New[string, int](3, nil)
	c.Put("a", 1)
	c.Put("b", 2)

	c.Clear()

	if c.Len() != 0 {
		t.Fatalf("expected len 0 after clear, got %d", c.Len())
	}

	// Reuse the cache.
	c.Put("x", 10)
	c.Put("y", 20)

	v, ok := c.Get("x")
	if !ok || v != 10 {
		t.Fatalf("expected (10, true), got (%d, %v)", v, ok)
	}
	if c.Len() != 2 {
		t.Fatalf("expected len 2, got %d", c.Len())
	}
}

// TestEviction_Order_FIFO_WhenNoAccess verifies eviction follows FIFO order
// when no entries are accessed (all equally old).
func TestEviction_Order_FIFO_WhenNoAccess(t *testing.T) {
	evicted := make([]string, 0)
	c := New[string, int](3, func(k string, v int) {
		evicted = append(evicted, k)
	})

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)
	c.Put("d", 4) // evicts a
	c.Put("e", 5) // evicts b
	c.Put("f", 6) // evicts c

	expected := []string{"a", "b", "c"}
	if len(evicted) != len(expected) {
		t.Fatalf("expected %d evictions, got %d: %v", len(expected), len(evicted), evicted)
	}
	for i, want := range expected {
		if evicted[i] != want {
			t.Errorf("eviction %d: expected %q, got %q", i, want, evicted[i])
		}
	}
}

// TestMaxSize_One verifies correct behavior with a single-element cache.
func TestMaxSize_One(t *testing.T) {
	evicted := make([]string, 0)
	c := New[string, int](1, func(k string, v int) {
		evicted = append(evicted, k)
	})

	c.Put("a", 1)
	v, ok := c.Get("a")
	if !ok || v != 1 {
		t.Fatalf("single element: expected (1, true), got (%d, %v)", v, ok)
	}

	c.Put("b", 2) // evicts a
	_, ok = c.Get("a")
	if ok {
		t.Fatal("expected 'a' to be evicted from size-1 cache")
	}

	v, ok = c.Get("b")
	if !ok || v != 2 {
		t.Fatalf("expected (2, true), got (%d, %v)", v, ok)
	}

	if len(evicted) != 1 || evicted[0] != "a" {
		t.Fatalf("expected eviction of 'a', got %v", evicted)
	}
}

// TestConcurrent_PutGetDelete exercises the cache under concurrent
// put, get, and delete operations to verify thread safety.
func TestConcurrent_PutGetDelete(t *testing.T) {
	c := New[int, int](50, nil)
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.Put(base*200+j, j)
			}
		}(i)
	}

	// Concurrent readers.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.Get(base*200 + j)
			}
		}(i)
	}

	// Concurrent deleters.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Delete(base*100 + j)
			}
		}(i)
	}

	wg.Wait()

	// Verify invariant: len should be <= maxSize.
	if c.Len() > 50 {
		t.Fatalf("cache exceeded max size: got %d", c.Len())
	}
}

// BenchmarkPutEviction benchmarks Put with constant eviction (cache always full).
func BenchmarkPutEviction(b *testing.B) {
	c := New[int, int](100, nil)
	// Pre-fill.
	for i := 0; i < 100; i++ {
		c.Put(i, i)
	}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c.Put(100+i, i)
	}
}

// BenchmarkGetMiss benchmarks Get for missing keys.
func BenchmarkGetMiss(b *testing.B) {
	c := New[int, int](100, nil)
	for i := 0; i < 100; i++ {
		c.Put(i, i)
	}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c.Get(100 + i) // always misses
	}
}

// BenchmarkConcurrentAccess benchmarks concurrent Put/Get.
func BenchmarkConcurrentAccess(b *testing.B) {
	c := New[int, int](1000, nil)
	for i := 0; i < 1000; i++ {
		c.Put(i, i)
	}
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				c.Put(i%2000, i)
			} else {
				c.Get(i % 1000)
			}
			i++
		}
	})
}

// TestNegativeMaxSize verifies that a negative max size defaults to 128.
func TestNegativeMaxSize(t *testing.T) {
	c := New[string, int](-5, nil)
	if c.maxSize != 128 {
		t.Fatalf("expected default maxSize 128 for negative input, got %d", c.maxSize)
	}
}

// TestLargeScaleEviction verifies eviction behavior with many entries.
func TestLargeScaleEviction(t *testing.T) {
	evictCount := 0
	c := New[int, int](100, func(k int, v int) {
		evictCount++
	})

	// Insert 1000 items into a cache of size 100.
	for i := 0; i < 1000; i++ {
		c.Put(i, i)
	}

	// Should have evicted 900 items.
	if evictCount != 900 {
		t.Fatalf("expected 900 evictions, got %d", evictCount)
	}

	// Only the last 100 items should remain.
	if c.Len() != 100 {
		t.Fatalf("expected len 100, got %d", c.Len())
	}

	// Items 0-899 should be gone.
	for i := 0; i < 900; i++ {
		_, ok := c.Get(i)
		if ok {
			t.Fatalf("expected item %d to be evicted", i)
		}
	}

	// Items 900-999 should exist.
	for i := 900; i < 1000; i++ {
		v, ok := c.Get(i)
		if !ok || v != i {
			t.Fatalf("expected item %d to exist with value %d", i, i)
		}
	}
}

// TestEvictCallback_WithStringer verifies evict callback works with interface types.
func TestEvictCallback_WithStringer(t *testing.T) {
	evicted := make([]string, 0)
	c := New[string, fmt.Stringer](2, func(k string, v fmt.Stringer) {
		evicted = append(evicted, k)
	})

	// Use a concrete type that satisfies fmt.Stringer.
	c.Put("a", stringWrapper("hello"))
	c.Put("b", stringWrapper("world"))
	c.Put("c", stringWrapper("new")) // evicts "a"

	if len(evicted) != 1 || evicted[0] != "a" {
		t.Fatalf("expected eviction of 'a', got %v", evicted)
	}
}

// stringWrapper is a simple type that implements fmt.Stringer.
type stringWrapper string

func (s stringWrapper) String() string { return string(s) }
