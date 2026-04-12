package cacher

import (
	"net/http"
	"testing"
)

func TestCacheKeyBuilder(t *testing.T) {
	t.Run("basic key building", func(t *testing.T) {
		key := NewCacheKeyBuilder().
			Add("part1").
			Add("part2").
			Add("part3").
			Build()

		expected := "part1:part2:part3"
		if key != expected {
			t.Errorf("expected %s, got %s", expected, key)
		}
	})

	t.Run("hashed key building", func(t *testing.T) {
		key := NewCacheKeyBuilder().
			Add("part1").
			Add("part2").
			BuildHashed()

		// Should be a 64-character hex string (SHA-256)
		if len(key) != 64 {
			t.Errorf("expected 64 character hash, got %d", len(key))
		}
	})

	t.Run("request cache key", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/path?foo=bar", nil)
		key := RequestCacheKey(req)

		// Should produce a consistent hash
		if len(key) != 64 {
			t.Errorf("expected 64 character hash, got %d", len(key))
		}

		// Same request should produce same key
		key2 := RequestCacheKey(req)
		if key != key2 {
			t.Error("same request should produce same cache key")
		}
	})

	t.Run("request cache key with headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/path", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-Custom", "value")

		key := RequestCacheKeyWithHeaders(req, "Authorization", "X-Custom")

		// Should be different from key without headers
		keyWithoutHeaders := RequestCacheKey(req)
		if key == keyWithoutHeaders {
			t.Error("key with headers should differ from key without headers")
		}
	})

	t.Run("session cache key", func(t *testing.T) {
		key := SessionCacheKey("session-123")
		expected := "session:session-123"

		if key != expected {
			t.Errorf("expected %s, got %s", expected, key)
		}
	})

	t.Run("callback cache key", func(t *testing.T) {
		key := CallbackCacheKey("https://api.example.com/callback", "POST")

		// Should produce a hash
		if len(key) != 64 {
			t.Errorf("expected 64 character hash, got %d", len(key))
		}
	})

	t.Run("token cache key", func(t *testing.T) {
		key := TokenCacheKey("jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")

		// Should produce a hash
		if len(key) != 64 {
			t.Errorf("expected 64 character hash, got %d", len(key))
		}
	})

	t.Run("origin cache key", func(t *testing.T) {
		key := OriginCacheKey("example.com")
		expected := "origin:example.com"

		if key != expected {
			t.Errorf("expected %s, got %s", expected, key)
		}
	})
}
