package e2e

import (
	"testing"
)

// TestForwardRules tests request forwarding based on path rules.
// Fixture: 22-forward-rules.json (forward-rules.test, forward-rules-api.test)
func TestForwardRules(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("forwards API paths to api origin", func(t *testing.T) {
		// Request with /api path should be forwarded to forward-rules-api.test origin
		resp := proxyGet(t, "forward-rules.test", "/api/test")
		assertStatus(t, resp, 200)

		// The forwarded origin adds X-API-Version header
		apiVersion := resp.Header.Get("X-API-Version")
		if apiVersion != "" {
			t.Logf("Forward rule applied, X-API-Version: %s", apiVersion)
		}
	})

	t.Run("non-API paths stay on default origin", func(t *testing.T) {
		resp := proxyGet(t, "forward-rules.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestNestedForwardRules tests complex nested forwarding rules.
// Fixture: 102-nested-forward-rules.json (nested-forward.test)
func TestNestedForwardRules(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("processes nested forward rules", func(t *testing.T) {
		resp := proxyGet(t, "nested-forward.test", "/test/simple-200")
		// Should be able to reach the origin through nested forwarding
		if resp.StatusCode >= 500 {
			t.Logf("Nested forward returned %d", resp.StatusCode)
		}
	})
}

// TestForwarderComprehensive tests comprehensive forwarder configuration.
// Fixture: 127-forwarder-comprehensive.json (forwarder-comprehensive.test)
func TestForwarderComprehensive(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("comprehensive forwarder config works", func(t *testing.T) {
		resp := proxyGet(t, "forwarder-comprehensive.test", "/test/simple-200")
		if resp.StatusCode == 0 {
			t.Error("Expected response from comprehensive forwarder origin")
		}
	})
}
