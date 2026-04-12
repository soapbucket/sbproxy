package origincache

import (
	"testing"
	"time"
)

func TestManager_GetOrCreate(t *testing.T) {
	m, err := NewCacheManager(CacheSystemConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	c1 := m.GetOrCreate("origin-1")
	c2 := m.GetOrCreate("origin-1")
	if c1 != c2 {
		t.Fatal("expected same cache instance for same origin")
	}

	c3 := m.GetOrCreate("origin-2")
	if c1 == c3 {
		t.Fatal("expected different cache for different origin")
	}

	if m.CacheCount() != 2 {
		t.Fatalf("expected 2 caches, got %d", m.CacheCount())
	}
}

func TestManager_Release(t *testing.T) {
	m, err := NewCacheManager(CacheSystemConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	c := m.GetOrCreate("origin-1")
	c.Set("key", []byte("val"), time.Hour)

	m.Release("origin-1")
	if m.CacheCount() != 0 {
		t.Fatalf("expected 0 caches after release, got %d", m.CacheCount())
	}

	// Getting again should create a fresh cache
	c2 := m.GetOrCreate("origin-1")
	if c2.Len() != 0 {
		t.Fatal("expected fresh empty cache after release")
	}
}

func TestManager_TotalUsedBytes(t *testing.T) {
	m, err := NewCacheManager(CacheSystemConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	c1 := m.GetOrCreate("origin-1")
	c2 := m.GetOrCreate("origin-2")

	c1.Set("k", []byte("val"), time.Hour)
	c2.Set("k", []byte("val"), time.Hour)

	total := m.TotalUsedBytes()
	if total <= 0 {
		t.Fatalf("expected positive total bytes, got %d", total)
	}
}

func TestManager_EncryptionKey(t *testing.T) {
	// Valid 32-byte key base64-encoded
	m, err := NewCacheManager(CacheSystemConfig{
		EncryptionKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	c := m.GetOrCreate("origin-1")
	c.Set("secret", []byte("sensitive"), time.Hour)

	val, ok := c.Get("secret")
	if !ok || string(val) != "sensitive" {
		t.Fatalf("expected sensitive, got %s", val)
	}
}

func TestManager_InvalidEncryptionKey(t *testing.T) {
	_, err := NewCacheManager(CacheSystemConfig{
		EncryptionKey: "not-valid-base64!!!",
	})
	if err == nil {
		t.Fatal("expected error for invalid encryption key")
	}
}

func TestManager_WrongSizeKey(t *testing.T) {
	_, err := NewCacheManager(CacheSystemConfig{
		EncryptionKey: "dG9vc2hvcnQ=", // "tooshort" base64
	})
	if err == nil {
		t.Fatal("expected error for wrong-size key")
	}
}
