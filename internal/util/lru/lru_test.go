package lru

import (
	"fmt"
	"sync"
	"testing"
)

func TestNew_DefaultSize(t *testing.T) {
	c := New[string, int](0, nil)
	if c.maxSize != 128 {
		t.Fatalf("expected default maxSize 128, got %d", c.maxSize)
	}
}

func TestPutAndGet(t *testing.T) {
	c := New[string, int](3, nil)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	v, ok := c.Get("a")
	if !ok || v != 1 {
		t.Fatalf("expected (1, true), got (%d, %v)", v, ok)
	}

	v, ok = c.Get("b")
	if !ok || v != 2 {
		t.Fatalf("expected (2, true), got (%d, %v)", v, ok)
	}

	_, ok = c.Get("missing")
	if ok {
		t.Fatal("expected false for missing key")
	}
}

func TestEviction(t *testing.T) {
	var evictedKey string
	var evictedVal int
	c := New[string, int](2, func(k string, v int) {
		evictedKey = k
		evictedVal = v
	})

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3) // should evict "a"

	if evictedKey != "a" || evictedVal != 1 {
		t.Fatalf("expected eviction of (a, 1), got (%s, %d)", evictedKey, evictedVal)
	}

	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected 'a' to be evicted")
	}

	if c.Len() != 2 {
		t.Fatalf("expected len 2, got %d", c.Len())
	}
}

func TestLRUOrdering(t *testing.T) {
	c := New[string, int](3, nil)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	// Access "a" to make it most recently used
	c.Get("a")

	// Adding "d" should evict "b" (least recently used)
	c.Put("d", 4)

	_, ok := c.Get("b")
	if ok {
		t.Fatal("expected 'b' to be evicted")
	}

	v, ok := c.Get("a")
	if !ok || v != 1 {
		t.Fatal("expected 'a' to still exist")
	}
}

func TestUpdate(t *testing.T) {
	c := New[string, int](2, nil)
	c.Put("a", 1)
	c.Put("a", 10) // update

	v, ok := c.Get("a")
	if !ok || v != 10 {
		t.Fatalf("expected (10, true), got (%d, %v)", v, ok)
	}

	if c.Len() != 1 {
		t.Fatalf("expected len 1 after update, got %d", c.Len())
	}
}

func TestDelete(t *testing.T) {
	c := New[string, int](3, nil)
	c.Put("a", 1)
	c.Put("b", 2)

	ok := c.Delete("a")
	if !ok {
		t.Fatal("expected Delete to return true for existing key")
	}

	ok = c.Delete("missing")
	if ok {
		t.Fatal("expected Delete to return false for missing key")
	}

	if c.Len() != 1 {
		t.Fatalf("expected len 1, got %d", c.Len())
	}
}

func TestClear(t *testing.T) {
	c := New[string, int](3, nil)
	c.Put("a", 1)
	c.Put("b", 2)

	c.Clear()

	if c.Len() != 0 {
		t.Fatalf("expected len 0 after clear, got %d", c.Len())
	}

	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected 'a' to be cleared")
	}
}

func TestConcurrency(t *testing.T) {
	c := New[int, int](100, nil)
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := base*100 + j
				c.Put(key, key)
				c.Get(key)
				c.Delete(key)
			}
		}(i)
	}

	wg.Wait()
}

func BenchmarkPut(b *testing.B) {
	c := New[int, int](1000, nil)
	for i := 0; i < b.N; i++ {
		c.Put(i%2000, i)
	}
}

func BenchmarkGet(b *testing.B) {
	c := New[int, int](1000, nil)
	for i := 0; i < 1000; i++ {
		c.Put(i, i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(i % 1000)
	}
}

func TestIntKeys(t *testing.T) {
	c := New[int, string](2, nil)
	c.Put(1, "one")
	c.Put(2, "two")

	v, ok := c.Get(1)
	if !ok || v != "one" {
		t.Fatalf("expected (one, true), got (%s, %v)", v, ok)
	}
}

func TestEvictionOrder(t *testing.T) {
	evicted := make([]string, 0)
	c := New[string, int](3, func(k string, _ int) {
		evicted = append(evicted, k)
	})

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)
	c.Put("d", 4) // evicts a
	c.Put("e", 5) // evicts b

	expected := []string{"a", "b"}
	if len(evicted) != len(expected) {
		t.Fatalf("expected %d evictions, got %d", len(expected), len(evicted))
	}
	for i, k := range expected {
		if evicted[i] != k {
			t.Fatalf("eviction %d: expected %s, got %s", i, k, evicted[i])
		}
	}
}

func TestSingleElement(t *testing.T) {
	c := New[string, int](1, nil)
	c.Put("a", 1)
	c.Put("b", 2) // evicts a

	_, ok := c.Get("a")
	if ok {
		t.Fatal("expected 'a' to be evicted")
	}

	v, ok := c.Get("b")
	if !ok || v != 2 {
		t.Fatalf("expected (2, true), got (%d, %v)", v, ok)
	}
}

func TestDeleteHeadAndTail(t *testing.T) {
	c := New[string, int](5, nil)
	c.Put("a", 1) // tail after all inserts
	c.Put("b", 2)
	c.Put("c", 3) // head after all inserts

	// Delete head
	c.Delete("c")
	if c.Len() != 2 {
		t.Fatalf("expected len 2, got %d", c.Len())
	}

	// Delete tail
	c.Delete("a")
	if c.Len() != 1 {
		t.Fatalf("expected len 1, got %d", c.Len())
	}

	v, ok := c.Get("b")
	if !ok || v != 2 {
		t.Fatal("expected 'b' to remain")
	}
}

func TestStringer(t *testing.T) {
	c := New[string, fmt.Stringer](2, nil)
	_ = c // just verifying it compiles with interface value types
}
