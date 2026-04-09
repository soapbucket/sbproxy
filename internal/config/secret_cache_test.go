package config

import (
	"sync"
	"testing"
)

func TestSecretCache_PutGet(t *testing.T) {
	cache, err := NewSecretCache()
	if err != nil {
		t.Fatalf("NewSecretCache() error: %v", err)
	}

	if err := cache.Put("api_key", "sk-12345"); err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	val, ok := cache.Get("api_key")
	if !ok {
		t.Fatal("Get() returned false, want true")
	}
	if val != "sk-12345" {
		t.Errorf("Get() = %q, want %q", val, "sk-12345")
	}
}

func TestSecretCache_GetMissing(t *testing.T) {
	cache, err := NewSecretCache()
	if err != nil {
		t.Fatalf("NewSecretCache() error: %v", err)
	}

	_, ok := cache.Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) returned true, want false")
	}
}

func TestSecretCache_GetAll(t *testing.T) {
	cache, err := NewSecretCache()
	if err != nil {
		t.Fatalf("NewSecretCache() error: %v", err)
	}

	secrets := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}
	for k, v := range secrets {
		if err := cache.Put(k, v); err != nil {
			t.Fatalf("Put(%q) error: %v", k, err)
		}
	}

	all := cache.GetAll()
	if len(all) != 3 {
		t.Fatalf("GetAll() returned %d items, want 3", len(all))
	}
	for k, want := range secrets {
		if got := all[k]; got != want {
			t.Errorf("GetAll()[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestSecretCache_ConcurrentAccess(t *testing.T) {
	cache, err := NewSecretCache()
	if err != nil {
		t.Fatalf("NewSecretCache() error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			key := "key" + string(rune('0'+n%10))
			_ = cache.Put(key, "value")
		}(i)
		go func(n int) {
			defer wg.Done()
			key := "key" + string(rune('0'+n%10))
			cache.Get(key)
		}(i)
	}
	wg.Wait()
}

func TestSecretCache_EphemeralKeyIsolation(t *testing.T) {
	cache1, err := NewSecretCache()
	if err != nil {
		t.Fatalf("NewSecretCache() #1 error: %v", err)
	}
	cache2, err := NewSecretCache()
	if err != nil {
		t.Fatalf("NewSecretCache() #2 error: %v", err)
	}

	if err := cache1.Put("secret", "hello"); err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	// cache2 should not be able to read cache1's data
	_, ok := cache2.Get("secret")
	if ok {
		t.Error("cache2 could read cache1's secret, expected isolation")
	}
}

func TestSecretCache_Len(t *testing.T) {
	cache, err := NewSecretCache()
	if err != nil {
		t.Fatalf("NewSecretCache() error: %v", err)
	}

	if cache.Len() != 0 {
		t.Errorf("Len() = %d, want 0", cache.Len())
	}

	_ = cache.Put("a", "1")
	_ = cache.Put("b", "2")
	if cache.Len() != 2 {
		t.Errorf("Len() = %d, want 2", cache.Len())
	}
}
