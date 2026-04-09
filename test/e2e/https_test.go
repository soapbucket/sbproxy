package e2e

import (
	"testing"
)

// TestHTTPSProxy tests HTTPS proxying.
// Fixture: 21-https-proxy.json (https-proxy.test)
func TestHTTPSProxy(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("serves content over HTTPS", func(t *testing.T) {
		resp := proxyHTTPS(t, "GET", "https-proxy.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})

	t.Run("serves content over HTTP", func(t *testing.T) {
		resp := proxyGet(t, "https-proxy.test", "/test/simple-200")
		// May redirect to HTTPS or serve directly
		if resp.StatusCode != 200 && resp.StatusCode != 301 && resp.StatusCode != 308 {
			t.Errorf("Expected 200, 301, or 308 for HTTP request to HTTPS origin, got %d", resp.StatusCode)
		}
	})
}

// TestCertificatePinning tests certificate pinning configuration.
// Fixture: 143-certificate-pinning.json (cert-pinning.test)
func TestCertificatePinning(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("certificate pinning origin responds", func(t *testing.T) {
		resp := proxyGet(t, "cert-pinning.test", "/test/simple-200")
		t.Logf("Certificate pinning origin response: %d", resp.StatusCode)
	})
}
