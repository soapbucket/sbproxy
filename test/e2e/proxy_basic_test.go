package e2e

import (
	"strings"
	"testing"
)

// TestBasicProxy tests basic proxy forwarding without any modifications.
// Fixture: 01-basic-proxy.json (basic-proxy.test)
func TestBasicProxy(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("forwards GET request to backend", func(t *testing.T) {
		resp := proxyGet(t, "basic-proxy.test", "/test/simple-200")
		assertStatus(t, resp, 200)
		assertContentType(t, resp, "application/json")
		assertJSON(t, resp, func(t *testing.T, data map[string]interface{}) {
			if data["status"] != "success" {
				t.Errorf("Expected status=success, got %v", data["status"])
			}
		})
	})

	t.Run("forwards root path", func(t *testing.T) {
		resp := proxyGet(t, "basic-proxy.test", "/")
		assertStatus(t, resp, 200)
	})

	t.Run("preserves request path", func(t *testing.T) {
		resp := proxyGet(t, "basic-proxy.test", "/test/json-response")
		assertStatus(t, resp, 200)
	})

	t.Run("returns 502 for unknown host", func(t *testing.T) {
		resp := proxyGet(t, "nonexistent-host.test", "/")
		// Proxy should return an error for unknown hosts
		if resp.StatusCode < 400 {
			t.Errorf("Expected error status for unknown host, got %d", resp.StatusCode)
		}
	})
}

// TestProxyWithHeaders tests proxy with request and response header modifications.
// Fixture: 02-proxy-with-headers.json (proxy-headers.test)
func TestProxyWithHeaders(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("sets custom response headers", func(t *testing.T) {
		resp := proxyGet(t, "proxy-headers.test", "/test/simple-200")
		assertStatus(t, resp, 200)
		// Response modifier should set X-Proxy-Response-Time header
		assertHeaderExists(t, resp, "X-Proxy-Response-Time")
		assertHeaderContains(t, resp, "X-Proxy-Response-Time", "ms")
	})

	t.Run("sets request headers for backend", func(t *testing.T) {
		// Request to /api/headers endpoint which echoes back headers
		resp := proxyGet(t, "proxy-headers.test", "/api/headers")
		assertStatus(t, resp, 200)
		assertContentType(t, resp, "application/json")
		// The backend should have received the X-Proxy-Request-ID header
		assertJSON(t, resp, func(t *testing.T, data map[string]interface{}) {
			headers, ok := data["headers"].(map[string]interface{})
			if !ok {
				t.Fatal("Expected headers in response")
			}
			if _, exists := headers["X-Proxy-Request-Id"]; !exists {
				// Check alternative header casing
				if _, exists := headers["X-Proxy-Request-ID"]; !exists {
					t.Error("Expected X-Proxy-Request-ID header to be forwarded to backend")
				}
			}
		})
	})
}

// TestProxyPathRewrite tests URL path rewriting.
// Fixture: 03-proxy-path-rewrite.json (proxy-rewrite.test)
func TestProxyPathRewrite(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("rewrites matching path", func(t *testing.T) {
		// /old-api/simple-200 should be rewritten to /test/simple-200
		resp := proxyGet(t, "proxy-rewrite.test", "/old-api/simple-200")
		assertStatus(t, resp, 200)
	})

	t.Run("does not rewrite non-matching path", func(t *testing.T) {
		// /test/simple-200 should pass through unchanged
		resp := proxyGet(t, "proxy-rewrite.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestProxyQueryParams tests query parameter modification.
// Fixture: 04-proxy-query-params.json (proxy-query.test)
func TestProxyQueryParams(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("adds query parameters", func(t *testing.T) {
		// Request /api/echo which echoes back the request including query params
		resp := proxyGet(t, "proxy-query.test", "/api/echo")
		assertStatus(t, resp, 200)
		assertJSON(t, resp, func(t *testing.T, data map[string]interface{}) {
			query, ok := data["query"].(map[string]interface{})
			if !ok {
				t.Fatal("Expected query in echo response")
			}
			// Should have the added 'source' parameter
			if source, exists := query["source"]; exists {
				sourceArr, ok := source.([]interface{})
				if ok && len(sourceArr) > 0 {
					if sourceArr[0] != "proxy" {
						t.Errorf("Expected source=proxy, got %v", sourceArr[0])
					}
				}
			} else {
				t.Error("Expected 'source' query parameter to be added")
			}
		})
	})

	t.Run("preserves existing query parameters", func(t *testing.T) {
		resp := proxyGet(t, "proxy-query.test", "/api/echo?existing=param")
		assertStatus(t, resp, 200)
		assertJSON(t, resp, func(t *testing.T, data map[string]interface{}) {
			query, ok := data["query"].(map[string]interface{})
			if !ok {
				t.Fatal("Expected query in echo response")
			}
			// Should preserve existing parameter
			if existing, exists := query["existing"]; exists {
				existingArr, ok := existing.([]interface{})
				if ok && len(existingArr) > 0 {
					if existingArr[0] != "param" {
						t.Errorf("Expected existing=param to be preserved, got %v", existingArr[0])
					}
				}
			} else {
				t.Error("Expected 'existing' query parameter to be preserved")
			}
		})
	})
}

// TestRedirectAction tests the redirect action type.
// Fixture: 10-redirect.json (redirect.test)
func TestRedirectAction(t *testing.T) {
	checkProxyReachable(t)

	t.Run("returns 301 redirect", func(t *testing.T) {
		resp := proxyGet(t, "redirect.test", "/some/path")
		assertRedirect(t, resp, 301, "example.com")
	})

	t.Run("preserves path in redirect", func(t *testing.T) {
		resp := proxyGet(t, "redirect.test", "/some/path")
		location := resp.Header.Get("Location")
		if !strings.Contains(location, "/some/path") {
			t.Errorf("Expected redirect to preserve path /some/path, got Location: %s", location)
		}
	})

	t.Run("preserves query string in redirect", func(t *testing.T) {
		resp := proxyGet(t, "redirect.test", "/path?foo=bar")
		location := resp.Header.Get("Location")
		if !strings.Contains(location, "foo=bar") {
			t.Errorf("Expected redirect to preserve query ?foo=bar, got Location: %s", location)
		}
	})
}

// TestStaticContent tests the static content action type.
// Fixture: 11-static-content.json (static.test)
func TestStaticContent(t *testing.T) {
	checkProxyReachable(t)

	t.Run("serves static HTML content", func(t *testing.T) {
		resp := proxyGet(t, "static.test", "/")
		assertStatus(t, resp, 200)
		assertContentType(t, resp, "text/html")
		assertBodyContains(t, resp, "This is static content served by the proxy")
	})

	t.Run("sets custom headers", func(t *testing.T) {
		resp := proxyGet(t, "static.test", "/")
		assertHeader(t, resp, "X-Custom-Header", "static-content")
	})

	t.Run("returns same content for any path", func(t *testing.T) {
		resp1 := proxyGet(t, "static.test", "/")
		resp2 := proxyGet(t, "static.test", "/any/other/path")
		assertStatus(t, resp2, 200)
		if resp1.BodyStr != resp2.BodyStr {
			t.Error("Expected same static content for any path")
		}
	})
}

// TestEchoEndpoint tests the echo action type.
// Fixture: Uses a proxy that forwards to test server /api/echo
func TestEchoEndpoint(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("echoes POST body through proxy", func(t *testing.T) {
		body := `{"test":"data","key":"value"}`
		resp := proxyPost(t, "basic-proxy.test", "/api/echo", body,
			"Content-Type", "application/json")
		assertStatus(t, resp, 200)
		assertJSON(t, resp, func(t *testing.T, data map[string]interface{}) {
			if data["method"] != "POST" {
				t.Errorf("Expected method=POST, got %v", data["method"])
			}
			if bodyStr, ok := data["body"].(string); ok {
				if !strings.Contains(bodyStr, "test") {
					t.Error("Expected body to contain the posted data")
				}
			}
		})
	})
}
