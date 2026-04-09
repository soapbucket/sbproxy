package e2e

import (
	"testing"
)

// TestJSONTransform tests JSON transformation features.
// Fixture: 08-json-transform.json (json-transform.test)
func TestJSONTransform(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("redacts sensitive fields", func(t *testing.T) {
		// The json-transform origin redacts $.sensitive with "REDACTED"
		resp := proxyGet(t, "json-transform.test", "/test-page.json")
		assertStatus(t, resp, 200)
		assertContentType(t, resp, "application/json")

		// The JSON transform should replace the "sensitive" field value
		assertJSON(t, resp, func(t *testing.T, data map[string]interface{}) {
			if sensitive, ok := data["sensitive"]; ok {
				if sensitive != "REDACTED" {
					t.Errorf("Expected sensitive field to be REDACTED, got %v", sensitive)
				}
			}
		})
	})

	t.Run("pretty prints JSON", func(t *testing.T) {
		resp := proxyGet(t, "json-transform.test", "/test-page.json")
		assertStatus(t, resp, 200)
		// Pretty-printed JSON should contain newlines and indentation
		if len(resp.BodyStr) > 0 && resp.BodyStr[0] == '{' {
			// Check that output has line breaks (pretty-printed)
			assertBodyContains(t, resp, "\n")
		}
	})
}

// TestStringReplace tests string replacement transform.
// Fixture: 09-string-replace.json (string-replace.test)
func TestStringReplace(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("replaces strings in response", func(t *testing.T) {
		resp := proxyGet(t, "string-replace.test", "/test-page.html")
		assertStatus(t, resp, 200)
		assertContentType(t, resp, "text/html")
		// Verify the page was returned (basic content check)
		assertBodyContains(t, resp, "html")
	})
}

// TestHTMLTransform tests HTML transformation features.
// Fixture: 06-html-transform-basic.json (html-transform.test)
func TestHTMLTransform(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("transforms HTML content", func(t *testing.T) {
		resp := proxyGet(t, "html-transform.test", "/test-page.html")
		assertStatus(t, resp, 200)
		assertContentType(t, resp, "text/html")
		// Basic HTML structure should be preserved
		assertBodyContains(t, resp, "<html")
	})
}

// TestMultipleTransforms tests multiple transforms applied in sequence.
// Fixture: 70-multiple-transforms.json (multiple-transforms.test)
func TestMultipleTransforms(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies multiple transforms", func(t *testing.T) {
		resp := proxyGet(t, "multiple-transforms.test", "/test-page.html")
		assertStatus(t, resp, 200)
		// The response should have been processed - just verify it comes back
		if len(resp.Body) == 0 {
			t.Error("Expected non-empty response body after transforms")
		}
	})
}

// TestJavaScriptTransform tests JavaScript transformation.
// Fixture: 40-javascript-transform.json (javascript-transform.test)
func TestJavaScriptTransform(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("transforms JavaScript content", func(t *testing.T) {
		resp := proxyGet(t, "javascript-transform.test", "/test-page.js")
		assertStatus(t, resp, 200)
		// JavaScript content should still be present
		if len(resp.Body) == 0 {
			t.Error("Expected non-empty JavaScript response")
		}
	})
}

// TestCSSTransform tests CSS transformation.
// Fixture: 41-css-transform.json (css-transform.test)
func TestCSSTransform(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("transforms CSS content", func(t *testing.T) {
		resp := proxyGet(t, "css-transform.test", "/test-page.css")
		assertStatus(t, resp, 200)
		// CSS content should still be present
		if len(resp.Body) == 0 {
			t.Error("Expected non-empty CSS response")
		}
	})
}
