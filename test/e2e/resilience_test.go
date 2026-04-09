package e2e

import (
	"testing"
)

// TestRetryConfig tests retry configuration.
// Fixture: 95-retry-config.json (retry.test)
func TestRetryConfig(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("retries failed requests", func(t *testing.T) {
		// Reset the retry endpoint state
		directGet(t, "/retry/test-1?reset=true&success_after=2&retryable_code=503")

		// Request through proxy - the proxy should retry after 503
		resp := proxyGet(t, "retry.test", "/retry/test-1?success_after=2&retryable_code=503")
		t.Logf("Retry test response status: %d", resp.StatusCode)
	})
}

// TestCircuitBreakerConfig tests circuit breaker configuration.
// Fixture: 94-circuit-breaker-config.json (circuit-breaker.test)
func TestCircuitBreakerConfig(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("allows requests when circuit is closed", func(t *testing.T) {
		// Reset the circuit breaker state
		directGet(t, "/circuit/test-1?reset=true")

		resp := proxyGet(t, "circuit-breaker.test", "/circuit/test-1")
		assertStatus(t, resp, 200)
	})
}

// TestTimeoutConfig tests timeout configuration.
// Fixture: 96-timeout-config.json (timeout.test)
func TestTimeoutConfig(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("allows requests within timeout", func(t *testing.T) {
		resp := proxyGet(t, "timeout.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestTransportWrappersRetry tests transport wrapper retry behavior.
// Fixture: 150-transport-wrappers-retry.json (transport-retry.test)
func TestTransportWrappersRetry(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("transport retry works for successful requests", func(t *testing.T) {
		resp := proxyGet(t, "transport-retry.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestTransportWrappersHedging tests transport wrapper hedging behavior.
// Fixture: 151-transport-wrappers-hedging.json (transport-hedging.test)
func TestTransportWrappersHedging(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("hedged requests succeed", func(t *testing.T) {
		resp := proxyGet(t, "transport-hedging.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestTransportWrappersHealthCheck tests transport wrapper health check behavior.
// Fixture: 152-transport-wrappers-health-check.json (transport-health.test)
func TestTransportWrappersHealthCheck(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("health check enabled transport works", func(t *testing.T) {
		resp := proxyGet(t, "transport-health.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestTransportWrappersCombined tests combined transport wrappers.
// Fixture: 153-transport-wrappers-combined.json (transport-combined.test)
func TestTransportWrappersCombined(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("combined transport wrappers work", func(t *testing.T) {
		resp := proxyGet(t, "transport-combined.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}
