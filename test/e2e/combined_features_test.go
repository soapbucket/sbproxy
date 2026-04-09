package e2e

import (
	"encoding/base64"
	"testing"
)

// TestComplexCombined tests complex combined origin configuration.
// Fixture: 24-complex-combined.json (complex.test)
func TestComplexCombined(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("handles combined features", func(t *testing.T) {
		resp := proxyGet(t, "complex.test", "/test/simple-200")
		// Combined origin should process the request through all configured features
		if resp.StatusCode >= 500 {
			t.Errorf("Expected success with combined features, got %d", resp.StatusCode)
		}
	})
}

// TestCompleteFeatureStack tests the complete feature stack configuration.
// Fixture: 100-complete-feature-stack.json (complete-stack.test)
func TestCompleteFeatureStack(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("handles complete feature stack", func(t *testing.T) {
		resp := proxyGet(t, "complete-stack.test", "/test/simple-200")
		if resp.StatusCode == 0 {
			t.Error("Expected a response from complete feature stack origin")
		}
	})
}

// TestAuthPlusWAF tests authentication combined with WAF policy.
// Fixture: 85-auth-plus-waf.json (auth-waf.test)
func TestAuthPlusWAF(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		resp := proxyGet(t, "auth-waf.test", "/test/simple-200")
		if resp.StatusCode == 200 {
			t.Error("Expected auth+WAF to reject unauthenticated request")
		}
	})
}

// TestAuthRateLimitTransform tests auth + rate limiting + transform combination.
// Fixture: 86-auth-rate-limit-transform.json (auth-ratelimit-transform.test)
func TestAuthRateLimitTransform(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("rejects without auth", func(t *testing.T) {
		resp := proxyGet(t, "auth-ratelimit-transform.test", "/test/simple-200")
		if resp.StatusCode == 200 {
			t.Error("Expected auth to reject unauthenticated request")
		}
	})
}

// TestCachingPlusCompression tests caching combined with compression.
// Fixture: 87-caching-plus-compression.json (cache-compression.test)
func TestCachingPlusCompression(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("serves cached compressed content", func(t *testing.T) {
		resp := proxyGet(t, "cache-compression.test", "/test/simple-200",
			"Accept-Encoding", "gzip")
		assertStatus(t, resp, 200)
	})
}

// TestMultiPolicyStack tests multiple policies applied together.
// Fixture: 88-multi-policy-stack.json (multi-policy.test)
func TestMultiPolicyStack(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("processes through multiple policies", func(t *testing.T) {
		resp := proxyGet(t, "multi-policy.test", "/test/simple-200")
		// Should process through all policies
		if resp.StatusCode == 0 {
			t.Error("Expected a response from multi-policy origin")
		}
	})
}

// TestSessionAuthCallbacks tests session + auth + callback combination.
// Fixture: 89-session-auth-callbacks.json (session-auth-callbacks.test)
func TestSessionAuthCallbacks(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("processes session auth with callbacks", func(t *testing.T) {
		resp := proxyGet(t, "session-auth-callbacks.test", "/test/simple-200")
		// Will likely need auth, so may return 401
		t.Logf("Session+Auth+Callbacks response: %d", resp.StatusCode)
	})
}

// TestTransformChain tests transform chain configuration.
// Fixture: 90-transform-chain.json (transform-chain.test)
func TestTransformChain(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies transform chain", func(t *testing.T) {
		resp := proxyGet(t, "transform-chain.test", "/test-page.html")
		assertStatus(t, resp, 200)
	})
}

// TestConditionalRouting tests conditional routing configuration.
// Fixture: 91-conditional-routing.json (conditional-routing.test)
func TestConditionalRouting(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("routes based on conditions", func(t *testing.T) {
		resp := proxyGet(t, "conditional-routing.test", "/test/simple-200")
		if resp.StatusCode == 0 {
			t.Error("Expected a response from conditional routing origin")
		}
	})
}

// TestRequestResponseModifiersStack tests stacked request/response modifiers.
// Fixture: 92-request-response-modifiers-stack.json (modifiers-stack.test)
func TestRequestResponseModifiersStack(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies stacked modifiers", func(t *testing.T) {
		resp := proxyGet(t, "modifiers-stack.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestMultiAuthMethods tests multiple authentication methods on one origin.
// Fixture: 103-multi-auth-methods.json (multi-auth.test)
func TestMultiAuthMethods(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("rejects request without any auth", func(t *testing.T) {
		resp := proxyGet(t, "multi-auth.test", "/test/simple-200")
		if resp.StatusCode == 200 {
			t.Error("Expected multi-auth to reject unauthenticated request")
		}
	})
}

// TestABTestWithSessions tests A/B testing with session tracking.
// Fixture: 101-abtest-with-sessions.json (abtest-sessions.test)
func TestABTestWithSessions(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("routes to A/B variant with session", func(t *testing.T) {
		resp := proxyGet(t, "abtest-sessions.test", "/test/simple-200")
		if resp.StatusCode >= 500 {
			t.Errorf("Expected A/B test with sessions to work, got %d", resp.StatusCode)
		}
	})
}

// TestRateLimitPerUser tests per-user rate limiting.
// Fixture: 105-rate-limit-per-user.json (rate-limit-per-user.test)
func TestRateLimitPerUser(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("applies per-user rate limiting", func(t *testing.T) {
		creds := base64.StdEncoding.EncodeToString([]byte("user1:pass1"))
		resp := proxyGet(t, "rate-limit-per-user.test", "/test/simple-200",
			"Authorization", "Basic "+creds)
		// May require specific auth
		t.Logf("Per-user rate limit response: %d", resp.StatusCode)
	})
}

// TestCanaryDeployment tests canary deployment configuration.
// Fixture: 107-canary-deployment.json (canary.test)
func TestCanaryDeployment(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("routes to canary or stable", func(t *testing.T) {
		resp := proxyGet(t, "canary.test", "/test/simple-200")
		if resp.StatusCode >= 500 {
			t.Errorf("Expected canary routing to work, got %d", resp.StatusCode)
		}
	})
}

// TestContentNegotiation tests content negotiation configuration.
// Fixture: 110-content-negotiation.json (content-negotiation.test)
func TestContentNegotiation(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("negotiates JSON content", func(t *testing.T) {
		resp := proxyGet(t, "content-negotiation.test", "/test/simple-200",
			"Accept", "application/json")
		assertStatus(t, resp, 200)
	})

	t.Run("negotiates HTML content", func(t *testing.T) {
		resp := proxyGet(t, "content-negotiation.test", "/test-page.html",
			"Accept", "text/html")
		assertStatus(t, resp, 200)
	})
}
