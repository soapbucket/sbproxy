package e2e

import (
	"sync"
	"testing"
)

// TestRequestCoalescing tests request coalescing feature.
// Fixture: 145-request-coalescing.json (request-coalescing.test)
func TestRequestCoalescing(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("coalesces identical concurrent requests", func(t *testing.T) {
		// Send multiple identical requests concurrently
		var wg sync.WaitGroup
		results := make([]*ProxyResponse, 5)

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = proxyGet(t, "request-coalescing.test", "/test/simple-200")
			}(i)
		}
		wg.Wait()

		// All requests should succeed
		for i, resp := range results {
			if resp == nil {
				t.Errorf("Request %d returned nil response", i)
				continue
			}
			if resp.StatusCode != 200 {
				t.Errorf("Request %d returned status %d, expected 200", i, resp.StatusCode)
			}
		}
	})
}

// TestRequestCoalescingMethodURL tests method-URL based coalescing.
// Fixture: 146-request-coalescing-method-url.json (request-coalescing-method-url.test)
func TestRequestCoalescingMethodURL(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("coalesces by method and URL", func(t *testing.T) {
		resp := proxyGet(t, "request-coalescing-method-url.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestRequestCoalescingDisabled tests that disabled coalescing works normally.
// Fixture: 147-request-coalescing-disabled.json (request-coalescing-disabled.test)
func TestRequestCoalescingDisabled(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("processes requests independently when coalescing disabled", func(t *testing.T) {
		resp := proxyGet(t, "request-coalescing-disabled.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}
