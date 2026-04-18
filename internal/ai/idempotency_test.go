package ai

import (
	"testing"
	"time"
)

func TestIdempotencyConfig_Defaults(t *testing.T) {
	cfg := IdempotencyConfig{}
	if cfg.HeaderName() != "Idempotency-Key" {
		t.Errorf("expected default header, got %q", cfg.HeaderName())
	}
	if cfg.TTL() != 300*time.Second {
		t.Errorf("expected default TTL 300s, got %v", cfg.TTL())
	}
}

func TestIdempotencyConfig_Custom(t *testing.T) {
	cfg := IdempotencyConfig{Header: "X-Request-ID", TTLSecs: 60}
	if cfg.HeaderName() != "X-Request-ID" {
		t.Errorf("expected custom header, got %q", cfg.HeaderName())
	}
	if cfg.TTL() != 60*time.Second {
		t.Errorf("expected 60s TTL, got %v", cfg.TTL())
	}
}

func TestNewIdempotencyCache_DefaultTTL(t *testing.T) {
	c := NewIdempotencyCache(0)
	if c.ttl != 300*time.Second {
		t.Errorf("expected default TTL, got %v", c.ttl)
	}
}

func TestIdempotencyCache_SetAndGet(t *testing.T) {
	c := NewIdempotencyCache(5 * time.Minute)

	headers := map[string]string{"Content-Type": "application/json"}
	c.Set("key1", []byte(`{"ok":true}`), 200, headers)

	body, status, hdrs, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if status != 200 {
		t.Errorf("expected status 200, got %d", status)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("unexpected body: %s", body)
	}
	if hdrs["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type header")
	}
}

func TestIdempotencyCache_GetMiss(t *testing.T) {
	c := NewIdempotencyCache(5 * time.Minute)

	_, _, _, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestIdempotencyCache_Expiration(t *testing.T) {
	c := NewIdempotencyCache(1 * time.Millisecond)

	c.Set("key1", []byte("data"), 200, nil)
	time.Sleep(5 * time.Millisecond)

	_, _, _, ok := c.Get("key1")
	if ok {
		t.Error("expected cache miss after expiration")
	}
}

func TestIdempotencyCache_CleanExpired(t *testing.T) {
	c := NewIdempotencyCache(1 * time.Millisecond)

	c.Set("key1", []byte("data1"), 200, nil)
	c.Set("key2", []byte("data2"), 200, nil)

	time.Sleep(5 * time.Millisecond)
	c.CleanExpired()

	if c.Len() != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", c.Len())
	}
}

func TestIdempotencyCache_Overwrite(t *testing.T) {
	c := NewIdempotencyCache(5 * time.Minute)

	c.Set("key1", []byte("v1"), 200, nil)
	c.Set("key1", []byte("v2"), 201, nil)

	body, status, _, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if status != 201 {
		t.Errorf("expected status 201, got %d", status)
	}
	if string(body) != "v2" {
		t.Errorf("expected v2, got %s", body)
	}
}

func TestIdempotencyCache_HeaderIsolation(t *testing.T) {
	c := NewIdempotencyCache(5 * time.Minute)

	original := map[string]string{"X-Test": "value"}
	c.Set("key1", []byte("data"), 200, original)

	// Mutate the original map
	original["X-Test"] = "mutated"

	_, _, hdrs, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if hdrs["X-Test"] != "value" {
		t.Errorf("expected original value, got %q", hdrs["X-Test"])
	}
}

func TestIdempotencyCache_Len(t *testing.T) {
	c := NewIdempotencyCache(5 * time.Minute)

	if c.Len() != 0 {
		t.Errorf("expected 0, got %d", c.Len())
	}

	c.Set("a", nil, 200, nil)
	c.Set("b", nil, 200, nil)

	if c.Len() != 2 {
		t.Errorf("expected 2, got %d", c.Len())
	}
}
