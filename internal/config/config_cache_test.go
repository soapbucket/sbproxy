package config

import (
	"testing"
	"time"
)

// TestLRUCache_GetSet verifies basic get/set operations.
func TestLRUCache_GetSet(t *testing.T) {
	lru := NewLRUCache(10)

	entry := &CacheEntry{
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Hash:      "abc123",
	}
	lru.Set("key1", entry)

	got, ok := lru.Get("key1")
	if !ok {
		t.Fatal("expected key1 to be found")
	}
	if got.Hash != "abc123" {
		t.Errorf("expected hash abc123, got %q", got.Hash)
	}
}

// TestLRUCache_Get_Missing verifies Get returns false for missing keys.
func TestLRUCache_Get_Missing(t *testing.T) {
	lru := NewLRUCache(10)

	_, ok := lru.Get("nonexistent")
	if ok {
		t.Error("expected false for missing key")
	}
}

// TestLRUCache_Get_Expired verifies Get returns false for expired entries.
func TestLRUCache_Get_Expired(t *testing.T) {
	lru := NewLRUCache(10)

	entry := &CacheEntry{
		ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
		Hash:      "expired",
	}
	lru.Set("expired-key", entry)

	_, ok := lru.Get("expired-key")
	if ok {
		t.Error("expected false for expired entry")
	}
}

// TestLRUCache_Eviction verifies LRU eviction when capacity is exceeded.
func TestLRUCache_Eviction(t *testing.T) {
	lru := NewLRUCache(3)

	for i := 0; i < 3; i++ {
		lru.Set(keyForIndex(i), &CacheEntry{
			ExpiresAt: time.Now().Add(5 * time.Minute),
			Hash:      keyForIndex(i),
		})
	}

	// Cache is full. Adding a 4th entry should evict the oldest (key0).
	lru.Set("key3", &CacheEntry{
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Hash:      "key3",
	})

	_, ok := lru.Get("key0")
	if ok {
		t.Error("expected key0 to be evicted (LRU)")
	}

	// key1, key2, key3 should still be present.
	for _, key := range []string{"key1", "key2", "key3"} {
		_, ok := lru.Get(key)
		if !ok {
			t.Errorf("expected %q to still exist", key)
		}
	}
}

// TestLRUCache_Eviction_AfterAccess verifies that accessed entries are promoted
// and not evicted prematurely.
func TestLRUCache_Eviction_AfterAccess(t *testing.T) {
	lru := NewLRUCache(3)

	lru.Set("a", &CacheEntry{ExpiresAt: time.Now().Add(5 * time.Minute), Hash: "a"})
	lru.Set("b", &CacheEntry{ExpiresAt: time.Now().Add(5 * time.Minute), Hash: "b"})
	lru.Set("c", &CacheEntry{ExpiresAt: time.Now().Add(5 * time.Minute), Hash: "c"})

	// Access "a" to promote it to MRU. Order: b, c, a.
	lru.Get("a")

	// Insert "d" - should evict "b" (LRU), not "a".
	lru.Set("d", &CacheEntry{ExpiresAt: time.Now().Add(5 * time.Minute), Hash: "d"})

	_, ok := lru.Get("b")
	if ok {
		t.Error("expected 'b' to be evicted after 'a' was promoted")
	}

	_, ok = lru.Get("a")
	if !ok {
		t.Error("expected 'a' to survive eviction after being accessed")
	}
}

// TestLRUCache_Update verifies that updating an existing key replaces the value
// and promotes the entry.
func TestLRUCache_Update(t *testing.T) {
	lru := NewLRUCache(3)

	lru.Set("a", &CacheEntry{ExpiresAt: time.Now().Add(5 * time.Minute), Hash: "v1"})
	lru.Set("b", &CacheEntry{ExpiresAt: time.Now().Add(5 * time.Minute), Hash: "v2"})

	// Update "a".
	lru.Set("a", &CacheEntry{ExpiresAt: time.Now().Add(5 * time.Minute), Hash: "v1-updated"})

	got, ok := lru.Get("a")
	if !ok {
		t.Fatal("expected 'a' to exist after update")
	}
	if got.Hash != "v1-updated" {
		t.Errorf("expected updated hash, got %q", got.Hash)
	}
}

// TestLRUCache_Clear verifies Clear removes all entries.
func TestLRUCache_Clear(t *testing.T) {
	lru := NewLRUCache(10)

	for i := 0; i < 5; i++ {
		lru.Set(keyForIndex(i), &CacheEntry{
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})
	}

	lru.Clear()

	lru.mu.RLock()
	itemCount := len(lru.items)
	orderLen := len(lru.order)
	lru.mu.RUnlock()

	if itemCount != 0 {
		t.Errorf("expected 0 items after clear, got %d", itemCount)
	}
	if orderLen != 0 {
		t.Errorf("expected 0 order entries after clear, got %d", orderLen)
	}
}

// TestNewConfigCache_Defaults verifies NewConfigCache applies default values.
func TestNewConfigCache_Defaults(t *testing.T) {
	cc := NewConfigCache("", 0, 0)

	if cc.ttl != 5*time.Minute {
		t.Errorf("expected default TTL 5m, got %v", cc.ttl)
	}
	if cc.lru.maxSize != 100 {
		t.Errorf("expected default LRU size 100, got %d", cc.lru.maxSize)
	}
}

// TestNewConfigCache_CustomValues verifies NewConfigCache respects custom values.
func TestNewConfigCache_CustomValues(t *testing.T) {
	cc := NewConfigCache("redis://localhost:6379", 50, 10*time.Minute)

	if cc.ttl != 10*time.Minute {
		t.Errorf("expected TTL 10m, got %v", cc.ttl)
	}
	if cc.lru.maxSize != 50 {
		t.Errorf("expected LRU size 50, got %d", cc.lru.maxSize)
	}
	if cc.redisURL != "redis://localhost:6379" {
		t.Errorf("expected redis URL, got %q", cc.redisURL)
	}
}

// keyForIndex generates a consistent key name for testing.
func keyForIndex(i int) string {
	return "key" + string(rune('0'+i))
}
