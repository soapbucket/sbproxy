package classifier

import (
	"testing"
	"time"
)

func TestEmbeddingCache_PutGet(t *testing.T) {
	cache := NewEmbeddingCache(100, 5*time.Minute)

	vec := []float32{0.1, 0.2, 0.3}
	cache.Put("hello world", vec)

	got, ok := cache.Get("hello world")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 3 || got[0] != 0.1 {
		t.Fatalf("unexpected embedding: %v", got)
	}
}

func TestEmbeddingCache_Miss(t *testing.T) {
	cache := NewEmbeddingCache(100, 5*time.Minute)

	_, ok := cache.Get("not stored")
	if ok {
		t.Fatal("expected cache miss")
	}

	hits, misses := cache.Stats()
	if hits != 0 || misses != 1 {
		t.Fatalf("expected 0 hits, 1 miss; got %d hits, %d misses", hits, misses)
	}
}

func TestEmbeddingCache_Eviction(t *testing.T) {
	cache := NewEmbeddingCache(2, 5*time.Minute)

	cache.Put("a", []float32{1})
	cache.Put("b", []float32{2})
	cache.Put("c", []float32{3}) // evicts "a"

	if _, ok := cache.Get("a"); ok {
		t.Fatal("expected 'a' to be evicted")
	}
	if _, ok := cache.Get("b"); !ok {
		t.Fatal("expected 'b' to still be cached")
	}
	if _, ok := cache.Get("c"); !ok {
		t.Fatal("expected 'c' to still be cached")
	}
	if cache.Len() != 2 {
		t.Fatalf("expected len 2, got %d", cache.Len())
	}
}

func TestEmbeddingCache_TTLExpiry(t *testing.T) {
	cache := NewEmbeddingCache(100, 1*time.Millisecond)

	cache.Put("short-lived", []float32{1, 2, 3})
	time.Sleep(5 * time.Millisecond)

	_, ok := cache.Get("short-lived")
	if ok {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestEmbeddingCache_UpdateInPlace(t *testing.T) {
	cache := NewEmbeddingCache(100, 5*time.Minute)

	cache.Put("key", []float32{1})
	cache.Put("key", []float32{2, 3})

	got, ok := cache.Get("key")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 2 || got[0] != 2 {
		t.Fatalf("expected updated value, got %v", got)
	}
	if cache.Len() != 1 {
		t.Fatalf("expected len 1 after update, got %d", cache.Len())
	}
}

func TestEmbeddingCache_Stats(t *testing.T) {
	cache := NewEmbeddingCache(100, 5*time.Minute)

	cache.Put("exists", []float32{1})

	cache.Get("exists") // hit
	cache.Get("exists") // hit
	cache.Get("nope")   // miss

	hits, misses := cache.Stats()
	if hits != 2 {
		t.Fatalf("expected 2 hits, got %d", hits)
	}
	if misses != 1 {
		t.Fatalf("expected 1 miss, got %d", misses)
	}
}

func TestHashKey_Deterministic(t *testing.T) {
	a := hashKey("same text")
	b := hashKey("same text")
	if a != b {
		t.Fatalf("hash not deterministic: %s != %s", a, b)
	}

	c := hashKey("different text")
	if a == c {
		t.Fatal("different text should produce different hash")
	}
}
