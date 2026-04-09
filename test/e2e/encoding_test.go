package e2e

import (
	"testing"
)

// TestEncodingFix tests encoding fix configuration.
// Fixture: 49-encoding-fix.json (encoding-fix.test)
func TestEncodingFix(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("fixes encoding in response", func(t *testing.T) {
		resp := proxyGet(t, "encoding-fix.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestContentTypeFix tests content type fix configuration.
// Fixture: 50-content-type-fix.json (content-type-fix.test)
func TestContentTypeFix(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("fixes content type in response", func(t *testing.T) {
		resp := proxyGet(t, "content-type-fix.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestEncodingFixComprehensive tests comprehensive encoding fix.
// Fixture: 134-encoding-fix-comprehensive.json (encoding-fix-comprehensive.test)
func TestEncodingFixComprehensive(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("comprehensive encoding fix works", func(t *testing.T) {
		resp := proxyGet(t, "encoding-fix-comprehensive.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestContentTypeFixComprehensive tests comprehensive content type fix.
// Fixture: 135-content-type-fix-comprehensive.json (content-type-fix-comprehensive.test)
func TestContentTypeFixComprehensive(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("comprehensive content type fix works", func(t *testing.T) {
		resp := proxyGet(t, "content-type-fix-comprehensive.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestStreamingConfig tests streaming configuration.
// Fixture: 66-streaming-config.json (streaming.test)
func TestStreamingConfig(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("handles streaming config", func(t *testing.T) {
		resp := proxyGet(t, "streaming.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}
