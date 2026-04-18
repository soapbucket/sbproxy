package ai

import (
	"encoding/json"
	"testing"
)

func TestSharedCacheKey(t *testing.T) {
	messages := []json.RawMessage{
		json.RawMessage(`{"role":"user","content":"Hello"}`),
		json.RawMessage(`{"role":"assistant","content":"Hi"}`),
	}

	key1 := SharedCacheKey(messages)
	if key1 == "" {
		t.Fatal("expected non-empty key")
	}

	// Same messages produce same key.
	key2 := SharedCacheKey(messages)
	if key1 != key2 {
		t.Errorf("expected same key for same messages, got %q and %q", key1, key2)
	}

	// Different messages produce different key.
	different := []json.RawMessage{
		json.RawMessage(`{"role":"user","content":"Goodbye"}`),
	}
	key3 := SharedCacheKey(different)
	if key1 == key3 {
		t.Error("expected different key for different messages")
	}
}

func TestSharedCacheKey_Empty(t *testing.T) {
	key := SharedCacheKey(nil)
	if key == "" {
		t.Fatal("expected non-empty key even for nil messages")
	}

	key2 := SharedCacheKey([]json.RawMessage{})
	if key != key2 {
		t.Error("expected same key for nil and empty slice")
	}
}

func TestNewSharedCache(t *testing.T) {
	cache := NewSharedCache(100)
	if cache == nil {
		t.Fatal("expected non-nil cache")
	}
	if cache.Size() != 0 {
		t.Errorf("expected size 0, got %d", cache.Size())
	}
}

func TestNewSharedCache_DefaultSize(t *testing.T) {
	cache := NewSharedCache(0)
	if cache.maxEntries != 1000 {
		t.Errorf("expected default max 1000, got %d", cache.maxEntries)
	}

	cache = NewSharedCache(-1)
	if cache.maxEntries != 1000 {
		t.Errorf("expected default max 1000, got %d", cache.maxEntries)
	}
}

func TestSharedCache_GetSet(t *testing.T) {
	cache := NewSharedCache(100)

	cache.Set("key1", []byte("response1"))

	val, ok := cache.Get("key1")
	if !ok {
		t.Fatal("expected to find key1")
	}
	if string(val) != "response1" {
		t.Errorf("expected 'response1', got %q", string(val))
	}

	// Missing key.
	_, ok = cache.Get("missing")
	if ok {
		t.Error("expected not found for missing key")
	}
}

func TestSharedCache_GetReturnsCopy(t *testing.T) {
	cache := NewSharedCache(100)
	cache.Set("key1", []byte("original"))

	val, _ := cache.Get("key1")
	val[0] = 'X' // mutate the returned value

	// Original should be unchanged.
	val2, _ := cache.Get("key1")
	if string(val2) != "original" {
		t.Errorf("cache was mutated: got %q", string(val2))
	}
}

func TestSharedCache_SetOverwrite(t *testing.T) {
	cache := NewSharedCache(100)

	cache.Set("key1", []byte("v1"))
	cache.Set("key1", []byte("v2"))

	val, _ := cache.Get("key1")
	if string(val) != "v2" {
		t.Errorf("expected 'v2', got %q", string(val))
	}

	if cache.Size() != 1 {
		t.Errorf("expected size 1, got %d", cache.Size())
	}
}

func TestSharedCache_Eviction(t *testing.T) {
	cache := NewSharedCache(3)

	cache.Set("k1", []byte("v1"))
	cache.Set("k2", []byte("v2"))
	cache.Set("k3", []byte("v3"))

	if cache.Size() != 3 {
		t.Errorf("expected size 3, got %d", cache.Size())
	}

	// Adding a 4th entry should evict one.
	cache.Set("k4", []byte("v4"))

	if cache.Size() != 3 {
		t.Errorf("expected size 3 after eviction, got %d", cache.Size())
	}

	// k4 should definitely be present.
	_, ok := cache.Get("k4")
	if !ok {
		t.Error("expected k4 to be present")
	}
}

func TestSharedCache_Delete(t *testing.T) {
	cache := NewSharedCache(100)

	cache.Set("key1", []byte("v1"))
	cache.Delete("key1")

	_, ok := cache.Get("key1")
	if ok {
		t.Error("expected key1 to be deleted")
	}

	if cache.Size() != 0 {
		t.Errorf("expected size 0, got %d", cache.Size())
	}
}

func TestSharedCache_Clear(t *testing.T) {
	cache := NewSharedCache(100)

	cache.Set("k1", []byte("v1"))
	cache.Set("k2", []byte("v2"))
	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", cache.Size())
	}
}
