package origincache

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestCache_GetSet(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{})

	// Set and get
	if err := c.Set("key1", []byte("value1"), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	val, ok := c.Get("key1")
	if !ok || string(val) != "value1" {
		t.Fatalf("expected value1, got %s (ok=%v)", val, ok)
	}

	// Missing key
	_, ok = c.Get("missing")
	if ok {
		t.Fatal("expected miss for missing key")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{
		DefaultTTL: time.Hour,
		MaxTTL:     time.Hour,
	})

	if err := c.Set("expire", []byte("val"), 1*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	_, ok := c.Get("expire")
	if ok {
		t.Fatal("expected expired key to miss")
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{
		MaxSizePerOriginMB: 1, // 1MB
		MaxKeySizeBytes:    1024,
		MaxValueSizeBytes:  1048576,
	})

	// Fill cache with large values
	bigVal := make([]byte, 512*1024) // 512KB each
	rand.Read(bigVal)

	c.Set("first", bigVal, time.Hour)
	c.Set("second", bigVal, time.Hour)

	// This should evict "first"
	c.Set("third", bigVal, time.Hour)

	_, ok := c.Get("first")
	if ok {
		t.Fatal("expected 'first' to be evicted by LRU")
	}
	_, ok = c.Get("third")
	if !ok {
		t.Fatal("expected 'third' to exist")
	}
}

func TestCache_KeyIsolation(t *testing.T) {
	c1 := NewOriginCache("origin-1", nil, CacheSystemConfig{})
	c2 := NewOriginCache("origin-2", nil, CacheSystemConfig{})

	c1.Set("shared-key", []byte("origin-1-value"), time.Hour)
	c2.Set("shared-key", []byte("origin-2-value"), time.Hour)

	v1, _ := c1.Get("shared-key")
	v2, _ := c2.Get("shared-key")

	if string(v1) != "origin-1-value" {
		t.Fatalf("expected origin-1-value, got %s", v1)
	}
	if string(v2) != "origin-2-value" {
		t.Fatalf("expected origin-2-value, got %s", v2)
	}
}

func TestCache_Encryption(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aeadCipher, err := NewAEADCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	c := NewOriginCache("origin-1", aeadCipher, CacheSystemConfig{})
	c.Set("secret", []byte("sensitive-data"), time.Hour)

	// Verify the stored value is encrypted (not plaintext)
	c.mu.RLock()
	raw := c.data[c.keyFor("secret")].value
	c.mu.RUnlock()
	if string(raw) == "sensitive-data" {
		t.Fatal("stored value should be encrypted, not plaintext")
	}

	// Verify Get returns decrypted value
	val, ok := c.Get("secret")
	if !ok || string(val) != "sensitive-data" {
		t.Fatalf("expected sensitive-data, got %s", val)
	}
}

func TestCache_Delete(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{})
	c.Set("key1", []byte("val"), time.Hour)
	c.Delete("key1")
	_, ok := c.Get("key1")
	if ok {
		t.Fatal("expected key to be deleted")
	}
}

func TestCache_Clear(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{})
	c.Set("k1", []byte("v1"), time.Hour)
	c.Set("k2", []byte("v2"), time.Hour)
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("expected 0 entries, got %d", c.Len())
	}
	if c.UsedBytes() != 0 {
		t.Fatalf("expected 0 bytes, got %d", c.UsedBytes())
	}
}

func TestCache_EvictExpired(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{
		DefaultTTL: time.Hour,
		MaxTTL:     time.Hour,
	})
	c.Set("short", []byte("val"), 1*time.Millisecond)
	c.Set("long", []byte("val"), time.Hour)
	time.Sleep(5 * time.Millisecond)

	evicted := c.EvictExpired()
	if evicted != 1 {
		t.Fatalf("expected 1 evicted, got %d", evicted)
	}
	if c.Len() != 1 {
		t.Fatalf("expected 1 remaining, got %d", c.Len())
	}
}

func TestCache_KeyTooLarge(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{MaxKeySizeBytes: 10})
	err := c.Set("this-key-is-way-too-long", []byte("val"), time.Hour)
	if err != ErrKeyTooLarge {
		t.Fatalf("expected ErrKeyTooLarge, got %v", err)
	}
}

func TestCache_ValueTooLarge(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{MaxValueSizeBytes: 10})
	err := c.Set("key", make([]byte, 100), time.Hour)
	if err != ErrValueTooLarge {
		t.Fatalf("expected ErrValueTooLarge, got %v", err)
	}
}

func TestCache_TTLClamped(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{MaxTTL: time.Minute})
	c.Set("key", []byte("val"), 24*time.Hour) // Requested 24h, should be clamped to 1m

	c.mu.RLock()
	e := c.data[c.keyFor("key")]
	ttlRemaining := time.Until(e.expiresAt)
	c.mu.RUnlock()

	if ttlRemaining > time.Minute+time.Second {
		t.Fatalf("TTL should be clamped to 1m, got %v", ttlRemaining)
	}
}

func TestCache_OverwriteExisting(t *testing.T) {
	c := NewOriginCache("origin-1", nil, CacheSystemConfig{})
	c.Set("key", []byte("original"), time.Hour)
	c.Set("key", []byte("updated"), time.Hour)

	val, ok := c.Get("key")
	if !ok || string(val) != "updated" {
		t.Fatalf("expected updated, got %s", val)
	}
	if c.Len() != 1 {
		t.Fatalf("expected 1 entry after overwrite, got %d", c.Len())
	}
}

func BenchmarkCache_Set(b *testing.B) {
	c := NewOriginCache("bench", nil, CacheSystemConfig{})
	val := []byte("benchmark-value")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set("key", val, time.Minute)
	}
}

func BenchmarkCache_Get(b *testing.B) {
	c := NewOriginCache("bench", nil, CacheSystemConfig{})
	c.Set("key", []byte("benchmark-value"), time.Hour)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get("key")
	}
}

func BenchmarkCache_SetEncrypted(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	aeadCipher, _ := NewAEADCipher(key)
	c := NewOriginCache("bench", aeadCipher, CacheSystemConfig{})
	val := []byte("benchmark-value")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set("key", val, time.Minute)
	}
}
