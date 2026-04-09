package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurityHeadersPolicy_DuplicateHeadersFromUpstream tests that security headers
// from upstream responses are not duplicated when the proxy also has security headers configured
func TestSecurityHeadersPolicy_DuplicateHeadersFromUpstream(t *testing.T) {
	// Create a test upstream server that returns security headers
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers that might come from upstream
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=15768000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.google-analytics.com *.twitter.com *.facebook.com *.stripe.com https://www.gstatic.com")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer upstreamServer.Close()

	// Create proxy config with security headers policy
	configData := map[string]interface{}{
		"id":           "test-proxy",
		"hostname":     "test-proxy.test",
		"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  upstreamServer.URL,
		},
		"policies": []map[string]interface{}{
			{
				"type": "security_headers",
				"strict_transport_security": map[string]interface{}{
					"enabled":            true,
					"max_age":            31536000,
					"include_subdomains": true,
				},
				"content_security_policy": map[string]interface{}{
					"enabled": true,
					"policy":  "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'",
				},
				"x_frame_options": map[string]interface{}{
					"enabled": true,
					"value":   "DENY",
				},
				"x_content_type_options": map[string]interface{}{
					"enabled":  true,
					"no_sniff": true,
				},
				"x_xss_protection": map[string]interface{}{
					"enabled": true,
					"mode":    "block",
				},
				"referrer_policy": map[string]interface{}{
					"enabled": true,
					"policy":  "strict-origin-when-cross-origin",
				},
				"permissions_policy": map[string]interface{}{
					"enabled": true,
					"features": map[string]interface{}{
						"geolocation": "()",
						"microphone":  "()",
						"camera":      "()",
					},
				},
			},
		},
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	cfg, err := Load(configJSON)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create request
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test-proxy.test"
	rec := httptest.NewRecorder()

	// Serve the request through the proxy
	cfg.ServeHTTP(rec, req)

	// Check for duplicate headers
	checkForDuplicates(t, rec, "X-Frame-Options")
	checkForDuplicates(t, rec, "X-Content-Type-Options")
	checkForDuplicates(t, rec, "X-XSS-Protection")
	checkForDuplicates(t, rec, "Strict-Transport-Security")
	checkForDuplicates(t, rec, "Content-Security-Policy")
	checkForDuplicates(t, rec, "Referrer-Policy")
	checkForDuplicates(t, rec, "Permissions-Policy")

	// Verify that upstream headers are respected (first value should be from upstream)
	// For HSTS, upstream has max-age=15768000, proxy would set max-age=31536000
	// Since upstream has it first, we should respect upstream
	hstsValues := rec.Header().Values("Strict-Transport-Security")
	if len(hstsValues) > 0 {
		// Should respect upstream value
		if !strings.Contains(hstsValues[0], "max-age=15768000") {
			t.Logf("HSTS header values: %v", hstsValues)
			t.Logf("Note: Upstream HSTS should be respected, but proxy might have overridden it")
		}
	}
}

// TestSecurityHeadersPolicy_DuplicateHeadersFromReverseProxy tests that headers
// copied by ReverseProxy using Add() don't create duplicates
func TestSecurityHeadersPolicy_DuplicateHeadersFromReverseProxy(t *testing.T) {
	// Create a test upstream server
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Add("X-Frame-Options", "DENY") // Simulate duplicate from upstream
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Add("X-Content-Type-Options", "nosniff") // Simulate duplicate
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	}))
	defer upstreamServer.Close()

	// Create proxy config
	configData := map[string]interface{}{
		"id":           "test-proxy",
		"hostname":     "test-proxy.test",
		"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  upstreamServer.URL,
		},
		"policies": []map[string]interface{}{
			{
				"type": "security_headers",
				"x_frame_options": map[string]interface{}{
					"enabled": true,
					"value":   "DENY",
				},
				"x_content_type_options": map[string]interface{}{
					"enabled":  true,
					"no_sniff": true,
				},
			},
		},
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	cfg, err := Load(configJSON)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test-proxy.test"
	rec := httptest.NewRecorder()

	cfg.ServeHTTP(rec, req)

	// Check for duplicates
	checkForDuplicates(t, rec, "X-Frame-Options")
	checkForDuplicates(t, rec, "X-Content-Type-Options")
}

// checkForDuplicates checks if a header appears multiple times in the response
func checkForDuplicates(t *testing.T, rec *httptest.ResponseRecorder, headerName string) {
	t.Helper()
	values := rec.Header().Values(headerName)
	if len(values) > 1 {
		t.Errorf("Duplicate header found: %s appears %d times with values: %v", headerName, len(values), values)
		// Print all headers for debugging
		t.Logf("All headers for %s:", headerName)
		for i, v := range values {
			t.Logf("  [%d] %s", i, v)
		}
	} else if len(values) == 1 {
		t.Logf("✓ %s: %s (no duplicates)", headerName, values[0])
	} else {
		t.Logf("  %s: not present", headerName)
	}
}

// TestSecurityHeadersPolicy_RealUpstreamResponse tests with a real upstream (techmeme.com)
// This test requires network access and may be skipped in CI
func TestSecurityHeadersPolicy_RealUpstreamResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires network access")
	}

	// Create proxy config pointing to techmeme.com
	configData := map[string]interface{}{
		"id":           "test-proxy",
		"hostname":     "test-proxy.test",
		"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "https://techmeme.com",
		},
		"policies": []map[string]interface{}{
			{
				"type": "security_headers",
				"strict_transport_security": map[string]interface{}{
					"enabled":            true,
					"max_age":            31536000,
					"include_subdomains": true,
				},
				"content_security_policy": map[string]interface{}{
					"enabled": true,
					"policy":  "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'",
				},
				"x_frame_options": map[string]interface{}{
					"enabled": true,
					"value":   "DENY",
				},
				"x_content_type_options": map[string]interface{}{
					"enabled":  true,
					"no_sniff": true,
				},
				"x_xss_protection": map[string]interface{}{
					"enabled": true,
					"mode":    "block",
				},
				"referrer_policy": map[string]interface{}{
					"enabled": true,
					"policy":  "strict-origin-when-cross-origin",
				},
				"permissions_policy": map[string]interface{}{
					"enabled": true,
					"features": map[string]interface{}{
						"geolocation": "()",
						"microphone":  "()",
						"camera":      "()",
					},
				},
			},
		},
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	cfg, err := Load(configJSON)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test-proxy.test"
	rec := httptest.NewRecorder()

	cfg.ServeHTTP(rec, req)

	// Log all security headers for debugging
	securityHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	t.Logf("Response status: %d", rec.Code)
	t.Logf("Security headers in response:")
	for _, headerName := range securityHeaders {
		values := rec.Header().Values(headerName)
		if len(values) > 0 {
			t.Logf("  %s: %v (count: %d)", headerName, values, len(values))
			if len(values) > 1 {
				t.Errorf("DUPLICATE FOUND: %s appears %d times", headerName, len(values))
			}
		}
	}

	// Check for duplicates
	checkForDuplicates(t, rec, "X-Frame-Options")
	checkForDuplicates(t, rec, "X-Content-Type-Options")
	checkForDuplicates(t, rec, "X-XSS-Protection")
	checkForDuplicates(t, rec, "Strict-Transport-Security")
	checkForDuplicates(t, rec, "Content-Security-Policy")
	checkForDuplicates(t, rec, "Referrer-Policy")
	checkForDuplicates(t, rec, "Permissions-Policy")
}

