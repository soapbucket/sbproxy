package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurityHeadersApplication tests that security headers are actually applied
func TestSecurityHeadersApplication(t *testing.T) {
	configJSON := `{
		"id": "security-headers-test",
		"hostname": "security-headers.test",
		"policies": [
			{
				"type": "security_headers",
				"enabled": true,
				"strict_transport_security": {
					"enabled": true,
					"max_age": 31536000,
					"include_subdomains": true,
					"preload": true
				},
				"x_frame_options": {
					"enabled": true,
					"value": "DENY"
				},
				"x_content_type_options": {
					"enabled": true,
					"no_sniff": true
				},
				"x_xss_protection": {
					"enabled": true,
					"mode": "block"
				},
				"referrer_policy": {
					"enabled": true,
					"policy": "strict-origin-when-cross-origin"
				}
			}
		],
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		}
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Create a test handler
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Apply policies
	var handler http.Handler = backendHandler
	for _, policy := range cfg.policies {
		handler = policy.Apply(handler)
	}

	req := httptest.NewRequest("GET", "http://security-headers.test/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Check for HSTS header
	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("Strict-Transport-Security header not found")
	} else if !strings.Contains(hsts, "max-age=31536000") {
		t.Errorf("HSTS header missing max-age: %s", hsts)
	}

	// Check for X-Frame-Options
	xfo := w.Header().Get("X-Frame-Options")
	if xfo != "DENY" {
		t.Errorf("Expected X-Frame-Options: DENY, got: %s", xfo)
	}

	// Check for X-Content-Type-Options
	xcto := w.Header().Get("X-Content-Type-Options")
	if xcto != "nosniff" {
		t.Errorf("Expected X-Content-Type-Options: nosniff, got: %s", xcto)
	}
}

// TestRequestModifiersApplication tests that request modifiers actually modify requests
func TestRequestModifiersApplication(t *testing.T) {
	configJSON := `{
		"id": "request-modifiers-test",
		"hostname": "request-modifiers.test",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"request_modifiers": [
			{
				"headers": {
					"set": {
						"X-Request-ID": "test-123",
						"X-Custom-Header": "test-value"
					}
				}
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Create a handler that captures the request
	var capturedReq *http.Request
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create a request
	req := httptest.NewRequest("GET", "http://request-modifiers.test/api/headers", nil)
	
	// Apply request modifiers
	err = cfg.RequestModifiers.Apply(req)
	if err != nil {
		t.Fatalf("Failed to apply request modifiers: %v", err)
	}

	// Verify headers were set
	requestID := req.Header.Get("X-Request-ID")
	if requestID == "" {
		t.Error("X-Request-ID header not set")
	}

	customHeader := req.Header.Get("X-Custom-Header")
	if customHeader != "test-value" {
		t.Errorf("Expected X-Custom-Header: test-value, got: %s", customHeader)
	}

	// Test that handler receives modified request
	w := httptest.NewRecorder()
	testHandler.ServeHTTP(w, req)

	if capturedReq == nil {
		t.Fatal("Handler was not called")
	}

	if capturedReq.Header.Get("X-Request-ID") == "" {
		t.Error("Request modifier header not present in captured request")
	}
}

// TestResponseModifiersApplication tests that response modifiers actually modify responses
func TestResponseModifiersApplication(t *testing.T) {
	configJSON := `{
		"id": "response-modifiers-test",
		"hostname": "response-modifiers.test",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"response_modifiers": [
			{
				"headers": {
					"set": {
						"X-Proxy-Version": "1.0.0",
						"X-Processed-By": "soapbucket"
					}
				}
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Create a test response
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:    make(http.Header),
		Body:       nil,
	}
	resp.Header.Set("Content-Type", "application/json")

	// Apply response modifiers
	err = cfg.ResponseModifiers.Apply(resp)
	if err != nil {
		t.Fatalf("Failed to apply response modifiers: %v", err)
	}

	// Verify headers were set
	proxyVersion := resp.Header.Get("X-Proxy-Version")
	if proxyVersion != "1.0.0" {
		t.Errorf("Expected X-Proxy-Version: 1.0.0, got: %s", proxyVersion)
	}

	processedBy := resp.Header.Get("X-Processed-By")
	if processedBy != "soapbucket" {
		t.Errorf("Expected X-Processed-By: soapbucket, got: %s", processedBy)
	}
}

// TestResponseModifiersWithRules tests response modifiers with matching rules
func TestResponseModifiersWithRules(t *testing.T) {
	configJSON := `{
		"id": "response-modifiers-rules-test",
		"hostname": "response-modifiers-rules.test",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"response_modifiers": [
			{
				"headers": {
					"set": {
						"X-Proxy-Version": "1.0.0"
					}
				},
				"rules": [
					{
						"status": {"min": 200, "max": 299}
					}
				]
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Test with matching status code
	t.Run("Matching status code", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:    make(http.Header),
			Body:       nil,
		}

		err = cfg.ResponseModifiers.Apply(resp)
		if err != nil {
			t.Fatalf("Failed to apply response modifiers: %v", err)
		}

		if resp.Header.Get("X-Proxy-Version") != "1.0.0" {
			t.Error("X-Proxy-Version header not set for matching status code")
		}
	})

	// Test with non-matching status code
	t.Run("Non-matching status code", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusNotFound,
			Header:    make(http.Header),
			Body:       nil,
		}

		err = cfg.ResponseModifiers.Apply(resp)
		if err != nil {
			t.Fatalf("Failed to apply response modifiers: %v", err)
		}

		// Header should not be set for non-matching status
		if resp.Header.Get("X-Proxy-Version") != "" {
			t.Error("X-Proxy-Version header should not be set for non-matching status code")
		}
	})
}

// TestCompressionEnabled tests that compression is enabled when configured
// Note: Compression is handled at the middleware level, not as a Config field
// This test verifies that DisableCompression flag works correctly
func TestCompressionEnabled(t *testing.T) {
	configJSON := `{
		"id": "compression-test",
		"hostname": "compression.test",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"disable_compression": false
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify compression is not disabled
	if cfg.DisableCompression {
		t.Error("Compression should not be disabled")
	}

	// Note: Actual compression happens in the middleware layer via compressor middleware
	// The compression config in fixtures is for documentation/testing purposes
	// but is handled by the compressor middleware, not as a Config field
}


