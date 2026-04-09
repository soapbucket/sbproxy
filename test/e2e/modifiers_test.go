package e2e

import (
	"testing"
)

// TestRequestModifiersComplex tests complex request modifier scenarios.
// Fixture: 71-request-modifiers-complex.json (request-modifiers-complex.test)
func TestRequestModifiersComplex(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies multiple request modifiers", func(t *testing.T) {
		resp := proxyGet(t, "request-modifiers-complex.test", "/api/headers")
		assertStatus(t, resp, 200)
		assertContentType(t, resp, "application/json")
	})
}

// TestResponseModifiersComplex tests complex response modifier scenarios.
// Fixture: 72-response-modifiers-complex.json (response-modifiers-complex.test)
func TestResponseModifiersComplex(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies multiple response modifiers", func(t *testing.T) {
		resp := proxyGet(t, "response-modifiers-complex.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestResponseModifierComprehensive tests the comprehensive response modifier fixture.
// Fixture: 128-response-modifier-comprehensive.json (response-modifier-comprehensive.test)
func TestResponseModifierComprehensive(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies comprehensive response modifiers", func(t *testing.T) {
		resp := proxyGet(t, "response-modifier-comprehensive.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestCORSHeaders tests CORS header injection via response modifiers.
// Fixture: 20-cors-headers.json (cors.test)
func TestCORSHeaders(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("sets CORS headers", func(t *testing.T) {
		resp := proxyGet(t, "cors.test", "/test/simple-200")
		assertStatus(t, resp, 200)
		assertHeader(t, resp, "Access-Control-Allow-Origin", "*")
		assertHeader(t, resp, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		assertHeader(t, resp, "Access-Control-Allow-Headers", "Content-Type, Authorization")
		assertHeader(t, resp, "Access-Control-Max-Age", "3600")
	})

	t.Run("CORS headers present on any path", func(t *testing.T) {
		resp := proxyGet(t, "cors.test", "/api/echo")
		assertStatus(t, resp, 200)
		assertHeader(t, resp, "Access-Control-Allow-Origin", "*")
	})
}

// TestConditionalModifiers tests proxy with conditional header modifications.
// Fixture: 05-proxy-conditional-modifiers.json (proxy-conditional.test)
func TestConditionalModifiers(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies modifiers for API path", func(t *testing.T) {
		resp := proxyGet(t, "proxy-conditional.test", "/api/test")
		assertStatus(t, resp, 200)
	})

	t.Run("applies modifiers for admin path with auth", func(t *testing.T) {
		resp := proxyGet(t, "proxy-conditional.test", "/admin/test",
			"Authorization", "Bearer test-token")
		assertStatus(t, resp, 200)
	})
}
