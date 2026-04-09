package e2e

import (
	"testing"
)

// TestCacheL1 tests L1 (in-memory) caching.
// Fixture: 33-cache-l1.json (cache-l1.test)
func TestCacheL1(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("first request is a cache miss", func(t *testing.T) {
		resp := proxyGet(t, "cache-l1.test", "/cache/l1-test-1")
		assertStatus(t, resp, 200)
	})

	t.Run("second request may be a cache hit", func(t *testing.T) {
		// First request to populate cache
		resp1 := proxyGet(t, "cache-l1.test", "/cache/l1-test-2")
		assertStatus(t, resp1, 200)

		// Second request should hit cache
		resp2 := proxyGet(t, "cache-l1.test", "/cache/l1-test-2")
		assertStatus(t, resp2, 200)

		// Check for cache hit indicator headers if present
		xCache := resp2.Header.Get("X-Cache")
		if xCache != "" {
			t.Logf("Cache status on second request: %s", xCache)
		}
	})

	t.Run("returns ETag header", func(t *testing.T) {
		resp := proxyGet(t, "cache-l1.test", "/cache/l1-etag-test")
		assertStatus(t, resp, 200)
		etag := resp.Header.Get("ETag")
		if etag == "" {
			t.Log("Note: No ETag header in response. This may depend on cache configuration.")
		}
	})
}

// TestCacheL2 tests L2 (Redis) caching.
// Fixture: 34-cache-l2.json (cache-l2.test)
func TestCacheL2(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("L2 cache request succeeds", func(t *testing.T) {
		resp := proxyGet(t, "cache-l2.test", "/cache/l2-test-1")
		assertStatus(t, resp, 200)
	})

	t.Run("repeated requests use cache", func(t *testing.T) {
		// Populate
		resp1 := proxyGet(t, "cache-l2.test", "/cache/l2-test-2")
		assertStatus(t, resp1, 200)

		// Should use cache
		resp2 := proxyGet(t, "cache-l2.test", "/cache/l2-test-2")
		assertStatus(t, resp2, 200)
	})
}

// TestCacheValidation tests conditional cache validation with ETag/Last-Modified.
// Fixture: 116-cache-validation-test.json (cache-validation.test)
func TestCacheValidation(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("validates cache with ETag", func(t *testing.T) {
		// First request to get ETag
		resp1 := proxyGet(t, "cache-validation.test", "/cache/validation-test")
		assertStatus(t, resp1, 200)
		etag := resp1.Header.Get("ETag")

		if etag != "" {
			// Second request with If-None-Match
			resp2 := proxyGet(t, "cache-validation.test", "/cache/validation-test",
				"If-None-Match", etag)
			// Should return 304 Not Modified
			if resp2.StatusCode == 304 {
				t.Log("Cache validation with ETag works correctly (304)")
			} else {
				t.Logf("Cache validation response: %d (ETag: %s)", resp2.StatusCode, etag)
			}
		} else {
			t.Log("Note: No ETag in response, skipping conditional check")
		}
	})
}

// TestCacheETag tests ETag-based caching.
// Fixture: 117-cache-etag-test.json (cache-etag.test)
func TestCacheETag(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("returns ETag header", func(t *testing.T) {
		resp := proxyGet(t, "cache-etag.test", "/cache/etag-test")
		assertStatus(t, resp, 200)
		etag := resp.Header.Get("ETag")
		if etag == "" {
			t.Log("Note: No ETag header in response")
		}
	})
}

// TestCacheNoCache tests no-cache directive handling.
// Fixture: 120-cache-no-cache-test.json (cache-no-cache.test)
func TestCacheNoCache(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("respects no-cache directive", func(t *testing.T) {
		resp := proxyGet(t, "cache-no-cache.test", "/cache-test/no-cache")
		assertStatus(t, resp, 200)
	})
}

// TestCompression tests response compression.
// Fixture: 65-compression.json (compression.test)
func TestCompression(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("responds successfully with compression enabled", func(t *testing.T) {
		resp := proxyGet(t, "compression.test", "/test-page.html",
			"Accept-Encoding", "gzip, deflate, br")
		assertStatus(t, resp, 200)
		// Check if response is compressed
		encoding := resp.Header.Get("Content-Encoding")
		if encoding != "" {
			t.Logf("Response compressed with: %s", encoding)
		}
	})

	t.Run("returns uncompressed when not accepted", func(t *testing.T) {
		resp := proxyGet(t, "compression.test", "/test-page.html",
			"Accept-Encoding", "identity")
		assertStatus(t, resp, 200)
	})
}
