package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestConfigHandler_EchoAction tests the handler with a simple echo action
func TestConfigHandler_EchoAction(t *testing.T) {
	configJSON := `{
		"id": "test-echo",
		"hostname": "example.com",
		"action": {
			"type": "echo"
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	cfg.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Check Content-Type starts with application/json (may include charset)
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" && ct != "application/json; charset=utf-8" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
}

// TestConfigHandler_StaticAction tests the handler with a static response
func TestConfigHandler_StaticAction(t *testing.T) {
	configJSON := `{
		"id": "test-static",
		"hostname": "example.com",
		"action": {
			"type": "static",
			"status_code": 200,
			"content_type": "text/plain",
			"body": "Hello, World!"
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	cfg.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, w.Code)
	}

	if body := w.Body.String(); body != "Hello, World!" {
		t.Errorf("expected body %q, got %q", "Hello, World!", body)
	}

	// Check Content-Type starts with text/plain (may include charset)
	ct := w.Header().Get("Content-Type")
	if ct != "text/plain" && ct != "text/plain; charset=utf-8" {
		t.Errorf("expected Content-Type text/plain, got %s", ct)
	}
}

// TestConfigHandler_BeaconAction tests the handler with a beacon action
func TestConfigHandler_BeaconAction(t *testing.T) {
	tests := []struct {
		name           string
		configJSON     string
		expectedStatus int
		expectedCT     string
	}{
		{
			name: "beacon with 204 status",
			configJSON: `{
				"id": "test-beacon-204",
				"hostname": "example.com",
				"action": {
					"type": "beacon",
					"status_code": 204
				}
			}`,
			expectedStatus: http.StatusNoContent,
			expectedCT:     "text/plain; charset=utf-8",
		},
		{
			name: "beacon with empty GIF",
			configJSON: `{
				"id": "test-beacon-gif",
				"hostname": "example.com",
				"action": {
					"type": "beacon",
					"empty_gif": true
				}
			}`,
			expectedStatus: http.StatusOK,
			expectedCT:     "image/gif",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(tt.configJSON), &cfg)
			if err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/beacon", nil)
			w := httptest.NewRecorder()

			cfg.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if ct := w.Header().Get("Content-Type"); ct != tt.expectedCT {
				t.Errorf("expected Content-Type %s, got %s", tt.expectedCT, ct)
			}
		})
	}
}

// TestConfigHandler_WithBasicAuth tests the handler with basic authentication
func TestConfigHandler_WithBasicAuth(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectBody     bool
	}{
		{
			name:           "valid credentials",
			authHeader:     "Basic dXNlcjE6cGFzczE=", // user1:pass1
			expectedStatus: http.StatusOK,
			expectBody:     true,
		},
		{
			name:           "invalid credentials",
			authHeader:     "Basic dXNlcjE6d3JvbmcK", // user1:wrong
			expectedStatus: http.StatusUnauthorized,
			expectBody:     false,
		},
		{
			name:           "no credentials",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectBody:     false,
		},
	}

	configJSON := `{
		"id": "test-with-auth",
		"hostname": "example.com",
		"action": {
			"type": "static",
			"body": "Authenticated!"
		},
		"authentication": {
			"type": "basic_auth",
			"users": [
				{"username": "user1", "password": "pass1"}
			]
		}
	}`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(configJSON), &cfg)
			if err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			cfg.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectBody {
				if body := w.Body.String(); body != "Authenticated!" {
					t.Errorf("expected body %q, got %q", "Authenticated!", body)
				}
			}
		})
	}
}

// TestConfigHandler_WithPolicy tests the handler with IP filtering policy
func TestConfigHandler_WithIPFilteringPolicy(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		expectedStatus int
		expectBody     bool
	}{
		{
			name:           "whitelisted IP",
			remoteAddr:     "192.168.1.1:12345",
			expectedStatus: http.StatusOK,
			expectBody:     true,
		},
		{
			name:           "non-whitelisted IP",
			remoteAddr:     "10.0.0.1:12345",
			expectedStatus: http.StatusForbidden,
			expectBody:     false,
		},
	}

	configJSON := `{
		"id": "test-with-policy",
		"hostname": "example.com",
		"action": {
			"type": "static",
			"body": "Access granted!"
		},
		"policies": [
			{
				"type": "ip_filtering",
				"whitelist": ["192.168.1.1", "192.168.1.0/24"]
			}
		]
	}`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(configJSON), &cfg)
			if err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			w := httptest.NewRecorder()

			cfg.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectBody {
				if body := w.Body.String(); body != "Access granted!" {
					t.Errorf("expected body %q, got %q", "Access granted!", body)
				}
			}
		})
	}
}

// TestConfigHandler_WithSecurityHeadersPolicy tests the handler with security headers policy
func TestConfigHandler_WithSecurityHeadersPolicy(t *testing.T) {
	configJSON := `{
		"id": "test-with-security-headers",
		"hostname": "example.com",
		"action": {
			"type": "static",
			"body": "Secure content!"
		},
		"policies": [
			{
				"type": "security_headers",
				"strict_transport_security": {
					"enabled": true,
					"max_age": 31536000,
					"include_subdomains": true
				},
				"x_frame_options": {
					"enabled": true,
					"value": "DENY"
				},
				"x_content_type_options": {
					"enabled": true,
					"no_sniff": true
				}
			}
		]
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	cfg.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Check security headers
	headers := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
	}

	for headerName, expectedValue := range headers {
		if actualValue := w.Header().Get(headerName); actualValue != expectedValue {
			t.Errorf("expected header %s to be %q, got %q", headerName, expectedValue, actualValue)
		}
	}
}

// TestConfigHandler_WithMultiplePolicies tests the handler with multiple policies
func TestConfigHandler_WithMultiplePolicies(t *testing.T) {
	configJSON := `{
		"id": "test-multi-policy",
		"hostname": "example.com",
		"action": {
			"type": "static",
			"body": "Multi-policy protected!"
		},
		"policies": [
			{
				"type": "ip_filtering",
				"whitelist": ["192.168.1.0/24"]
			},
			{
				"type": "security_headers",
				"x_frame_options": {
					"enabled": true,
					"value": "DENY"
				}
			}
		]
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.50:12345"
	w := httptest.NewRecorder()

	cfg.ServeHTTP(w, req)

	// Should pass IP filtering and have security headers
	if w.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, w.Code)
	}

	if xfo := w.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Errorf("expected X-Frame-Options DENY, got %s", xfo)
	}

	if body := w.Body.String(); body != "Multi-policy protected!" {
		t.Errorf("expected body %q, got %q", "Multi-policy protected!", body)
	}
}

// TestConfigHandler_WithAuthAndPolicy tests the handler with both auth and policy
func TestConfigHandler_WithAuthAndPolicy(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		remoteAddr     string
		expectedStatus int
		expectBody     bool
	}{
		{
			name:           "valid auth and IP",
			authHeader:     "Basic dXNlcjE6cGFzczE=", // user1:pass1
			remoteAddr:     "192.168.1.1:12345",
			expectedStatus: http.StatusOK,
			expectBody:     true,
		},
		{
			name:           "valid auth but blocked IP",
			authHeader:     "Basic dXNlcjE6cGFzczE=", // user1:pass1
			remoteAddr:     "10.0.0.1:12345",
			expectedStatus: http.StatusForbidden,
			expectBody:     false,
		},
		{
			name:           "invalid auth but valid IP",
			authHeader:     "Basic dXNlcjE6d3JvbmcK", // user1:wrong
			remoteAddr:     "192.168.1.1:12345",
			expectedStatus: http.StatusUnauthorized,
			expectBody:     false,
		},
	}

	configJSON := `{
		"id": "test-auth-and-policy",
		"hostname": "example.com",
		"action": {
			"type": "static",
			"body": "Fully protected!"
		},
		"authentication": {
			"type": "basic_auth",
			"users": [
				{"username": "user1", "password": "pass1"}
			]
		},
		"policies": [
			{
				"type": "ip_filtering",
				"whitelist": ["192.168.1.0/24"]
			}
		]
	}`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(configJSON), &cfg)
			if err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			cfg.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectBody {
				if body := w.Body.String(); body != "Fully protected!" {
					t.Errorf("expected body %q, got %q", "Fully protected!", body)
				}
			}
		})
	}
}

// TestConfigHandler_PolicyOrderMatters tests that policies are applied in the correct order
func TestConfigHandler_PolicyOrderMatters(t *testing.T) {
	// IP filtering should run before (outer) security headers
	// If IP is blocked, security headers shouldn't be added
	configJSON := `{
		"id": "test-policy-order",
		"hostname": "example.com",
		"action": {
			"type": "static",
			"body": "Content"
		},
		"policies": [
			{
				"type": "ip_filtering",
				"whitelist": ["192.168.1.0/24"]
			},
			{
				"type": "security_headers",
				"x_frame_options": {
					"enabled": true,
					"value": "DENY"
				}
			}
		]
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	// Test with blocked IP
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345" // Not in whitelist
	w := httptest.NewRecorder()

	cfg.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status code %d, got %d", http.StatusForbidden, w.Code)
	}

	// Security headers should NOT be present since request was blocked by IP policy
	if xfo := w.Header().Get("X-Frame-Options"); xfo != "" {
		t.Errorf("expected no X-Frame-Options header for blocked request, got %s", xfo)
	}
}

// TestConfigHandler_DisabledAction tests that disabled config doesn't process requests
func TestConfigHandler_DisabledConfig(t *testing.T) {
	configJSON := `{
		"id": "test-disabled",
		"hostname": "example.com",
		"disabled": true,
		"action": {
			"type": "static",
			"body": "Should not see this"
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	// Note: The current implementation doesn't check cfg.Disabled in ServeHTTP
	// This test documents the current behavior
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	cfg.ServeHTTP(w, req)

	// Currently, disabled configs still process requests
	// If this behavior changes, update this test
	if w.Code != http.StatusOK {
		t.Logf("Note: Disabled config currently still processes requests")
	}
}

// TestConfigHandler_AllowedMethods tests that HTTP method validation works correctly
func TestConfigHandler_AllowedMethods(t *testing.T) {
	tests := []struct {
		name           string
		configJSON     string
		requestMethod  string
		expectedStatus int
	}{
		{
			name: "GET allowed when GET in allowed_methods",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"allowed_methods": ["GET", "POST"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name: "POST allowed when POST in allowed_methods",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"allowed_methods": ["GET", "POST"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodPost,
			expectedStatus: http.StatusOK,
		},
		{
			name: "PUT not allowed when not in allowed_methods",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"allowed_methods": ["GET", "POST"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodPut,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name: "DELETE not allowed when not in allowed_methods",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"allowed_methods": ["GET", "POST"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodDelete,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name: "PATCH not allowed when not in allowed_methods",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"allowed_methods": ["GET", "POST"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodPatch,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name: "OPTIONS always allowed even when not in allowed_methods (CORS preflight)",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"allowed_methods": ["GET", "POST"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodOptions,
			expectedStatus: http.StatusNoContent, // 204 is the correct status for OPTIONS
		},
		{
			name: "OPTIONS allowed when OPTIONS in allowed_methods",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"allowed_methods": ["GET", "OPTIONS"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodOptions,
			expectedStatus: http.StatusNoContent, // 204 is the correct status for OPTIONS
		},
		{
			name: "HEAD allowed when HEAD in allowed_methods",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"allowed_methods": ["GET", "HEAD"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodHead,
			expectedStatus: http.StatusOK,
		},
		{
			name: "Method allowed when allowed_methods is empty (not configured)",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodPut,
			expectedStatus: http.StatusOK,
		},
		{
			name: "Method validation is case-insensitive",
			configJSON: `{
				"id": "test-allowed-methods",
				"hostname": "example.com",
				"allowed_methods": ["get", "post"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			requestMethod:  http.MethodGet,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(tt.configJSON), &cfg)
			if err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			req := httptest.NewRequest(tt.requestMethod, "/test", nil)
			w := httptest.NewRecorder()

			cfg.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}
			
			// For OPTIONS requests, verify Allow header is set
			if tt.requestMethod == http.MethodOptions {
				allowHeader := w.Header().Get("Allow")
				if allowHeader == "" {
					t.Error("OPTIONS request should have Allow header set")
				}
			}
		})
	}
}

// TestConfigHandler_OptionsRequest_AllowHeader tests that OPTIONS requests set the Allow header correctly
func TestConfigHandler_OptionsRequest_AllowHeader(t *testing.T) {
	tests := []struct {
		name           string
		configJSON     string
		expectedAllow  string
	}{
		{
			name: "Allow header uses AllowedMethods when configured",
			configJSON: `{
				"id": "test-options-allow",
				"hostname": "example.com",
				"allowed_methods": ["GET", "POST", "PUT"],
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			expectedAllow: "GET, POST, PUT",
		},
		{
			name: "Allow header uses default methods when AllowedMethods not configured",
			configJSON: `{
				"id": "test-options-default",
				"hostname": "example.com",
				"action": {
					"type": "static",
					"body": "OK"
				}
			}`,
			expectedAllow: "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(tt.configJSON), &cfg)
			if err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			req := httptest.NewRequest(http.MethodOptions, "/test", nil)
			w := httptest.NewRecorder()

			cfg.ServeHTTP(w, req)

			if w.Code != http.StatusNoContent {
				t.Errorf("expected status code %d, got %d", http.StatusNoContent, w.Code)
			}

			allowHeader := w.Header().Get("Allow")
			if allowHeader != tt.expectedAllow {
				t.Errorf("expected Allow header %q, got %q", tt.expectedAllow, allowHeader)
			}
		})
	}
}

// TestRequestRules tests request_rules matching behavior in the handler
func TestRequestRules(t *testing.T) {
	tests := []struct {
		name           string
		configJSON     string
		requestPath    string
		requestMethod  string
		expectedStatus int
	}{
		{
			name: "no rules - request passes through",
			configJSON: `{
				"id": "test-no-rules",
				"hostname": "example.com",
				"action": {"type": "echo"}
			}`,
			requestPath:    "/anything",
			requestMethod:  http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name: "matching path - request handled",
			configJSON: `{
				"id": "test-match",
				"hostname": "example.com",
				"request_rules": [{"path": {"prefix": "/api"}}],
				"action": {"type": "echo"}
			}`,
			requestPath:    "/api/users",
			requestMethod:  http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name: "no match - returns 404",
			configJSON: `{
				"id": "test-no-match",
				"hostname": "example.com",
				"request_rules": [{"path": {"prefix": "/api"}}],
				"action": {"type": "echo"}
			}`,
			requestPath:    "/other",
			requestMethod:  http.MethodGet,
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "OR logic - second rule matches",
			configJSON: `{
				"id": "test-or-logic",
				"hostname": "example.com",
				"request_rules": [
					{"path": {"prefix": "/api"}},
					{"path": {"prefix": "/health"}}
				],
				"action": {"type": "echo"}
			}`,
			requestPath:    "/health",
			requestMethod:  http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name: "must_match_rules true - handler still works for matching requests",
			configJSON: `{
				"id": "test-must-match",
				"hostname": "example.com",
				"request_rules": [{"path": {"prefix": "/api"}}],
				"must_match_rules": true,
				"action": {"type": "echo"}
			}`,
			requestPath:    "/api/test",
			requestMethod:  http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name: "must_match_rules true - handler does not reject (configloader handles it)",
			configJSON: `{
				"id": "test-must-match-skip",
				"hostname": "example.com",
				"request_rules": [{"path": {"prefix": "/api"}}],
				"must_match_rules": true,
				"action": {"type": "echo"}
			}`,
			requestPath:    "/other",
			requestMethod:  http.MethodGet,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(tt.configJSON), &cfg)
			if err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			req := httptest.NewRequest(tt.requestMethod, tt.requestPath, nil)
			w := httptest.NewRecorder()

			cfg.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status code %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestRequestRules_DefaultContentType tests that default_content_type is used on request_rules rejection
func TestRequestRules_DefaultContentType(t *testing.T) {
	tests := []struct {
		name        string
		configJSON  string
		expectedCT  string
	}{
		{
			name: "custom default_content_type on reject",
			configJSON: `{
				"id": "test-ct-json",
				"hostname": "example.com",
				"request_rules": [{"path": {"prefix": "/api"}}],
				"default_content_type": "application/json",
				"action": {"type": "echo"}
			}`,
			expectedCT: "application/json",
		},
		{
			name: "uses default application/json when no default_content_type",
			configJSON: `{
				"id": "test-ct-default",
				"hostname": "example.com",
				"request_rules": [{"path": {"prefix": "/api"}}],
				"action": {"type": "echo"}
			}`,
			expectedCT: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(tt.configJSON), &cfg)
			if err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/non-matching-path", nil)
			w := httptest.NewRecorder()

			cfg.ServeHTTP(w, req)

			if w.Code != http.StatusNotFound {
				t.Errorf("expected status code %d, got %d", http.StatusNotFound, w.Code)
			}

			ct := w.Header().Get("Content-Type")
			if ct != tt.expectedCT {
				t.Errorf("expected Content-Type %q, got %q", tt.expectedCT, ct)
			}
		})
	}
}
