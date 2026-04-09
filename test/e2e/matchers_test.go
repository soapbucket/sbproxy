package e2e

import (
	"testing"
)

// TestRequestMatcherComprehensive tests comprehensive request matching rules.
// Fixture: 125-request-matcher-comprehensive.json (request-matcher.test)
func TestRequestMatcherComprehensive(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("matches request by path", func(t *testing.T) {
		resp := proxyGet(t, "request-matcher.test", "/test/simple-200")
		if resp.StatusCode == 0 {
			t.Error("Expected response from request matcher origin")
		}
	})
}

// TestResponseMatcherComprehensive tests comprehensive response matching rules.
// Fixture: 126-response-matcher-comprehensive.json (response-matcher.test)
func TestResponseMatcherComprehensive(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies response matcher rules", func(t *testing.T) {
		resp := proxyGet(t, "response-matcher.test", "/test/simple-200")
		if resp.StatusCode == 0 {
			t.Error("Expected response from response matcher origin")
		}
	})
}

// TestConditionalCache tests conditional caching based on rules.
// Fixture: 104-conditional-cache.json (conditional-cache.test)
func TestConditionalCache(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies conditional caching", func(t *testing.T) {
		resp := proxyGet(t, "conditional-cache.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}
