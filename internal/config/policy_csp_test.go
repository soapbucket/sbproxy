package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewSecurityHeadersPolicy_WithCSP(t *testing.T) {
	data := []byte(`{
		"type": "security_headers",
		"content_security_policy": {
			"enabled": true,
			"policy": "default-src 'self'; script-src 'self'"
		}
	}`)

	policy, err := NewSecurityHeadersPolicy(data)
	if err != nil {
		t.Fatalf("NewSecurityHeadersPolicy() error = %v", err)
	}

	cfg := &Config{ID: "test-config"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	shPolicy := policy.(*SecurityHeadersPolicyConfig)
	if shPolicy.ContentSecurityPolicy == nil {
		t.Fatal("ContentSecurityPolicy should not be nil")
	}
	if !shPolicy.ContentSecurityPolicy.Enabled {
		t.Error("CSP should be enabled")
	}
	if shPolicy.ContentSecurityPolicy.Policy == "" {
		t.Error("CSP policy should not be empty")
	}
}

func TestSecurityHeadersPolicy_ApplyCSP(t *testing.T) {
	data := []byte(`{
		"type": "security_headers",
		"content_security_policy": {
			"enabled": true,
			"policy": "default-src 'self'; script-src 'self'"
		}
	}`)

	policy, err := NewSecurityHeadersPolicy(data)
	if err != nil {
		t.Fatalf("NewSecurityHeadersPolicy() error = %v", err)
	}

	cfg := &Config{ID: "test-config"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Next handler should have been called")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	cspHeader := rec.Header().Get("Content-Security-Policy")
	if cspHeader == "" {
		t.Error("Content-Security-Policy header should be set")
	}
	if !strings.Contains(cspHeader, "default-src 'self'") {
		t.Errorf("CSP header should contain 'default-src 'self'', got %q", cspHeader)
	}
}

func TestSecurityHeadersPolicy_CSPReportOnly(t *testing.T) {
	data := []byte(`{
		"type": "security_headers",
		"content_security_policy": {
			"enabled": true,
			"report_only": true,
			"policy": "default-src 'self'"
		}
	}`)

	policy, err := NewSecurityHeadersPolicy(data)
	if err != nil {
		t.Fatalf("NewSecurityHeadersPolicy() error = %v", err)
	}

	cfg := &Config{ID: "test-config"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	cspHeader := rec.Header().Get("Content-Security-Policy-Report-Only")
	if cspHeader == "" {
		t.Error("Content-Security-Policy-Report-Only header should be set")
	}

	// Should not have regular CSP header
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("Content-Security-Policy header should not be set in report-only mode")
	}
}

func TestSecurityHeadersPolicy_CSPWithNonce(t *testing.T) {
	data := []byte(`{
		"type": "security_headers",
		"content_security_policy": {
			"enabled": true,
			"enable_nonce": true,
			"directives": {
				"script_src": ["'self'"]
			}
		}
	}`)

	policy, err := NewSecurityHeadersPolicy(data)
	if err != nil {
		t.Fatalf("NewSecurityHeadersPolicy() error = %v", err)
	}

	cfg := &Config{ID: "test-config"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	cspHeader := rec.Header().Get("Content-Security-Policy")
	if cspHeader == "" {
		t.Error("Content-Security-Policy header should be set")
	}
	if !strings.Contains(cspHeader, "'nonce-") {
		t.Errorf("CSP header should contain nonce, got %q", cspHeader)
	}

	// Check that nonce header is set
	nonceHeader := rec.Header().Get("X-CSP-Nonce")
	if nonceHeader == "" {
		t.Error("X-CSP-Nonce header should be set")
	}
}

func TestSecurityHeadersPolicy_CSPWithReportURI(t *testing.T) {
	data := []byte(`{
		"type": "security_headers",
		"content_security_policy": {
			"enabled": true,
			"policy": "default-src 'self'",
			"report_uri": "/csp-report"
		}
	}`)

	policy, err := NewSecurityHeadersPolicy(data)
	if err != nil {
		t.Fatalf("NewSecurityHeadersPolicy() error = %v", err)
	}

	cfg := &Config{ID: "test-config"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	cspHeader := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(cspHeader, "report-uri /csp-report") {
		t.Errorf("CSP header should contain report-uri, got %q", cspHeader)
	}
}

func TestSecurityHeadersPolicy_CSPDynamicRoutes(t *testing.T) {
	data := []byte(`{
		"type": "security_headers",
		"content_security_policy": {
			"enabled": true,
			"directives": {
				"default_src": ["'self'"]
			},
			"dynamic_routes": {
				"/admin": {
					"enabled": true,
					"directives": {
						"default_src": ["'self'"],
						"script_src": ["'self'"]
					}
				}
			}
		}
	}`)

	policy, err := NewSecurityHeadersPolicy(data)
	if err != nil {
		t.Fatalf("NewSecurityHeadersPolicy() error = %v", err)
	}

	cfg := &Config{ID: "test-config"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	tests := []struct {
		name         string
		path         string
		wantContains string
	}{
		{"default route", "/public", "default-src 'self'"},
		{"admin route", "/admin", "script-src 'self'"},
		{"admin subroute", "/admin/users", "script-src 'self'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := policy.Apply(next)
			handler.ServeHTTP(rec, req)

			cspHeader := rec.Header().Get("Content-Security-Policy")
			if !strings.Contains(cspHeader, tt.wantContains) {
				t.Errorf("CSP header for path %q should contain %q, got %q", tt.path, tt.wantContains, cspHeader)
			}
		})
	}
}

func TestSecurityHeadersPolicy_CSPDisabled(t *testing.T) {
	data := []byte(`{
		"type": "security_headers",
		"content_security_policy": {
			"enabled": false,
			"policy": "default-src 'self'"
		}
	}`)

	policy, err := NewSecurityHeadersPolicy(data)
	if err != nil {
		t.Fatalf("NewSecurityHeadersPolicy() error = %v", err)
	}

	cfg := &Config{ID: "test-config"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	cspHeader := rec.Header().Get("Content-Security-Policy")
	if cspHeader != "" {
		t.Errorf("Content-Security-Policy header should not be set when disabled, got %q", cspHeader)
	}
}

func TestSecurityHeadersPolicy_CSPStructuredDirectives(t *testing.T) {
	data := []byte(`{
		"type": "security_headers",
		"content_security_policy": {
			"enabled": true,
			"directives": {
				"default_src": ["'self'"],
				"script_src": ["'self'", "https://trusted-cdn.com"],
				"style_src": ["'self'", "'unsafe-inline'"],
				"img_src": ["'self'", "data:", "https:"],
				"frame_ancestors": ["'none'"],
				"upgrade_insecure_requests": true
			}
		}
	}`)

	policy, err := NewSecurityHeadersPolicy(data)
	if err != nil {
		t.Fatalf("NewSecurityHeadersPolicy() error = %v", err)
	}

	cfg := &Config{ID: "test-config"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	cspHeader := rec.Header().Get("Content-Security-Policy")
	if cspHeader == "" {
		t.Fatal("Content-Security-Policy header should be set")
	}

	// Verify all directives are present
	expectedParts := []string{
		"default-src 'self'",
		"script-src 'self' https://trusted-cdn.com",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: https:",
		"frame-ancestors 'none'",
		"upgrade-insecure-requests",
	}

	for _, part := range expectedParts {
		if !strings.Contains(cspHeader, part) {
			t.Errorf("CSP header should contain %q, got %q", part, cspHeader)
		}
	}
}

func TestConfigHandler_WithCSPPolicy(t *testing.T) {
	configJSON := `{
		"id": "test-with-csp",
		"hostname": "example.com",
		"action": {
			"type": "static",
			"body": "Secure content!"
		},
		"policies": [
			{
				"type": "security_headers",
				"content_security_policy": {
					"enabled": true,
					"policy": "default-src 'self'; script-src 'self'"
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

	cspHeader := w.Header().Get("Content-Security-Policy")
	if cspHeader == "" {
		t.Error("Content-Security-Policy header should be set")
	}
	if !strings.Contains(cspHeader, "default-src 'self'") {
		t.Errorf("CSP header should contain 'default-src 'self'', got %q", cspHeader)
	}
}

