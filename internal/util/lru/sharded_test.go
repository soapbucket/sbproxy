package lru

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestShardedCache_BasicGetPut(t *testing.T) {
	c := NewSharded[string, int](64, nil)

	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	if v, ok := c.Get("a"); !ok || v != 1 {
		t.Fatalf("Get(a) = (%d, %v), want (1, true)", v, ok)
	}
	if v, ok := c.Get("b"); !ok || v != 2 {
		t.Fatalf("Get(b) = (%d, %v), want (2, true)", v, ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Fatal("Get(missing) should return false")
	}
	if c.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", c.Len())
	}
}

func TestShardedCache_Delete(t *testing.T) {
	c := NewSharded[string, int](64, nil)
	c.Put("x", 10)

	if !c.Delete("x") {
		t.Fatal("Delete(x) should return true")
	}
	if c.Delete("x") {
		t.Fatal("Delete(x) second call should return false")
	}
	if _, ok := c.Get("x"); ok {
		t.Fatal("Get(x) after delete should return false")
	}
}

func TestShardedCache_Clear(t *testing.T) {
	c := NewSharded[string, int](64, nil)
	for i := 0; i < 20; i++ {
		c.Put(fmt.Sprintf("k%d", i), i)
	}
	if c.Len() == 0 {
		t.Fatal("cache should not be empty before Clear")
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("Len() after Clear = %d, want 0", c.Len())
	}
}

func TestShardedCache_Eviction(t *testing.T) {
	var evicted atomic.Int32
	onEvict := func(key string, value int) {
		evicted.Add(1)
	}

	// Total size 16, so each shard gets 1 slot. Inserting many keys forces evictions.
	c := NewSharded[string, int](16, onEvict)
	for i := 0; i < 100; i++ {
		c.Put(fmt.Sprintf("key-%d", i), i)
	}

	if evicted.Load() == 0 {
		t.Fatal("expected at least one eviction with small per-shard capacity")
	}
	// Total items should not exceed total capacity (16 shards * 1 per shard = 16).
	if c.Len() > 16 {
		t.Fatalf("Len() = %d, exceeds total capacity 16", c.Len())
	}
}

func TestShardedCache_EvictionSmallTotal(t *testing.T) {
	// totalSize smaller than numShards: each shard should get at least 1.
	var evicted atomic.Int32
	onEvict := func(key int, value string) {
		evicted.Add(1)
	}

	c := NewSharded[int, string](4, onEvict)
	for i := 0; i < 100; i++ {
		c.Put(i, fmt.Sprintf("val-%d", i))
	}

	if evicted.Load() == 0 {
		t.Fatal("expected evictions when totalSize < numShards")
	}
	// Each of 16 shards has capacity 1, so max items = 16.
	if c.Len() > 16 {
		t.Fatalf("Len() = %d, should be at most 16", c.Len())
	}
}

func TestShardedCache_ConcurrentAccess(t *testing.T) {
	c := NewSharded[string, int](1024, nil)
	const goroutines = 32
	const opsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				key := fmt.Sprintf("g%d-k%d", id, i)
				c.Put(key, i)
				c.Get(key)
				if i%3 == 0 {
					c.Delete(key)
				}
			}
		}(g)
	}

	wg.Wait()

	// Just verify it did not panic or deadlock and Len is sane.
	if c.Len() < 0 {
		t.Fatal("Len() should not be negative")
	}
}

func TestShardedCache_ShardDistribution(t *testing.T) {
	c := NewSharded[string, int](1600, nil)

	// Insert 1600 keys and check they spread across shards.
	for i := 0; i < 1600; i++ {
		c.Put(fmt.Sprintf("item-%d", i), i)
	}

	// Check each shard has at least some entries (statistical, but 1600 keys
	// across 16 shards should give at least a few per shard with FNV).
	for i, shard := range c.shards {
		count := shard.Len()
		if count == 0 {
			t.Errorf("shard %d has 0 entries out of 1600 total - poor distribution", i)
		}
	}

	totalFromShards := 0
	for _, shard := range c.shards {
		totalFromShards += shard.Len()
	}
	if totalFromShards != c.Len() {
		t.Fatalf("sum of shard lengths (%d) != Len() (%d)", totalFromShards, c.Len())
	}
}

func TestShardedCache_UpdateExisting(t *testing.T) {
	c := NewSharded[string, string](64, nil)
	c.Put("key", "v1")
	c.Put("key", "v2")

	if v, ok := c.Get("key"); !ok || v != "v2" {
		t.Fatalf("Get(key) = (%q, %v), want (v2, true)", v, ok)
	}
	if c.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 after update", c.Len())
	}
}

func TestShardedCache_DefaultSize(t *testing.T) {
	c := NewSharded[string, int](0, nil)
	// Should not panic; defaults to 128 total (8 per shard).
	for i := 0; i < 200; i++ {
		c.Put(fmt.Sprintf("k%d", i), i)
	}
	if c.Len() == 0 {
		t.Fatal("cache should contain entries after puts")
	}
}
