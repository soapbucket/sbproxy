package e2e

import (
	"testing"
)

// TestErrorPages tests custom error page configuration.
// Fixture: 36-error-pages.json (error-pages.test)
func TestErrorPages(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("shows custom 404 error page", func(t *testing.T) {
		// Request a path that returns 404 from the backend
		resp := proxyGet(t, "error-pages.test", "/test/not-found")
		assertStatus(t, resp, 404)
		// The custom error page should override the backend's 404
		assertContentType(t, resp, "text/html")
		assertBodyContains(t, resp, "404")
		assertBodyContains(t, resp, "Not Found")
	})

	t.Run("shows custom 503 error page as JSON", func(t *testing.T) {
		// Request a path that returns 503 from the backend
		resp := proxyGet(t, "error-pages.test", "/test/error-503")
		assertStatus(t, resp, 503)
		assertContentType(t, resp, "application/json")
		assertBodyContains(t, resp, "Service Unavailable")
	})
}

// TestErrorPagesComprehensive tests comprehensive error page configurations.
// Fixture: 138-error-pages-comprehensive.json (error-pages-comprehensive.test)
func TestErrorPagesComprehensive(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("handles comprehensive error pages", func(t *testing.T) {
		resp := proxyGet(t, "error-pages-comprehensive.test", "/test/not-found")
		assertStatus(t, resp, 404)
	})
}

// TestCallbacks tests callback configuration.
// Fixture: 23-callbacks.json (callbacks.test)
func TestCallbacks(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("origin with callbacks responds", func(t *testing.T) {
		resp := proxyGet(t, "callbacks.test", "/test/simple-200")
		// Origin with callbacks should still process requests normally
		if resp.StatusCode >= 500 {
			t.Errorf("Expected success status with callbacks configured, got %d", resp.StatusCode)
		}
	})
}

// TestCallbackComprehensive tests comprehensive callback configurations.
// Fixture: 129-callback-comprehensive.json (callback-comprehensive.test)
func TestCallbackComprehensive(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("comprehensive callbacks work", func(t *testing.T) {
		resp := proxyGet(t, "callback-comprehensive.test", "/test/simple-200")
		if resp.StatusCode >= 500 {
			t.Errorf("Expected success with comprehensive callbacks, got %d", resp.StatusCode)
		}
	})
}
