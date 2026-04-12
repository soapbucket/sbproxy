package secheaders

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNew_ValidConfig verifies that valid configs create an enforcer.
func TestNew_ValidConfig(t *testing.T) {
	cfg := Config{
		Type: "security_headers",
		StrictTransportSecurity: &HSTSConfig{
			Enabled: true,
			MaxAge:  31536000,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if enforcer == nil {
		t.Fatal("expected non-nil enforcer")
	}
}

// TestNew_InvalidJSON verifies that invalid JSON returns an error.
func TestNew_InvalidJSON(t *testing.T) {
	_, err := New(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestType verifies the Type() method returns the correct string.
func TestType(t *testing.T) {
	cfg := Config{Type: "security_headers"}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sh := enforcer.(*secHeadersPolicy)
	if sh.Type() != "security_headers" {
		t.Errorf("expected type 'security_headers', got %q", sh.Type())
	}
}

// TestEnforce_Disabled verifies that disabled policy passes through without headers.
func TestEnforce_Disabled(t *testing.T) {
	cfg := Config{
		Type:     "security_headers",
		Disabled: true,
		StrictTransportSecurity: &HSTSConfig{
			Enabled: true,
			MaxAge:  31536000,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called when policy is disabled")
	}
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("expected no HSTS header when policy is disabled")
	}
}

// TestEnforce_HSTS verifies HSTS header is applied.
func TestEnforce_HSTS(t *testing.T) {
	tests := []struct {
		name     string
		config   *HSTSConfig
		expected string
	}{
		{
			name:     "basic",
			config:   &HSTSConfig{Enabled: true, MaxAge: 3600},
			expected: "max-age=3600",
		},
		{
			name:     "with subdomains",
			config:   &HSTSConfig{Enabled: true, MaxAge: 3600, IncludeSubdomains: true},
			expected: "max-age=3600; includeSubDomains",
		},
		{
			name:     "with preload",
			config:   &HSTSConfig{Enabled: true, MaxAge: 3600, IncludeSubdomains: true, Preload: true},
			expected: "max-age=3600; includeSubDomains; preload",
		},
		{
			name:     "disabled",
			config:   &HSTSConfig{Enabled: false, MaxAge: 3600},
			expected: "",
		},
		{
			name:     "zero max age",
			config:   &HSTSConfig{Enabled: true, MaxAge: 0},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Type:                    "security_headers",
				StrictTransportSecurity: tc.config,
			}
			data, _ := json.Marshal(cfg)

			enforcer, err := New(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := enforcer.Enforce(next)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			got := w.Header().Get("Strict-Transport-Security")
			if got != tc.expected {
				t.Errorf("expected HSTS %q, got %q", tc.expected, got)
			}
		})
	}
}

// TestEnforce_XFrameOptions verifies X-Frame-Options header.
func TestEnforce_XFrameOptions(t *testing.T) {
	tests := []struct {
		name     string
		config   *XFrameOptionsConfig
		expected string
	}{
		{
			name:     "DENY",
			config:   &XFrameOptionsConfig{Enabled: true, Value: "DENY"},
			expected: "DENY",
		},
		{
			name:     "SAMEORIGIN",
			config:   &XFrameOptionsConfig{Enabled: true, Value: "SAMEORIGIN"},
			expected: "SAMEORIGIN",
		},
		{
			name:     "disabled",
			config:   &XFrameOptionsConfig{Enabled: false, Value: "DENY"},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Type:          "security_headers",
				XFrameOptions: tc.config,
			}
			data, _ := json.Marshal(cfg)

			enforcer, err := New(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := enforcer.Enforce(next)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			got := w.Header().Get("X-Frame-Options")
			if got != tc.expected {
				t.Errorf("expected X-Frame-Options %q, got %q", tc.expected, got)
			}
		})
	}
}

// TestEnforce_XContentTypeOptions verifies X-Content-Type-Options header.
func TestEnforce_XContentTypeOptions(t *testing.T) {
	cfg := Config{
		Type: "security_headers",
		XContentTypeOptions: &XContentTypeOptionsConfig{
			Enabled: true,
			NoSniff: true,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	got := w.Header().Get("X-Content-Type-Options")
	if got != "nosniff" {
		t.Errorf("expected 'nosniff', got %q", got)
	}
}

// TestEnforce_ReferrerPolicy verifies Referrer-Policy header.
func TestEnforce_ReferrerPolicy(t *testing.T) {
	validPolicies := []string{
		"no-referrer",
		"no-referrer-when-downgrade",
		"origin",
		"origin-when-cross-origin",
		"same-origin",
		"strict-origin",
		"strict-origin-when-cross-origin",
		"unsafe-url",
	}

	for _, policy := range validPolicies {
		t.Run(policy, func(t *testing.T) {
			cfg := Config{
				Type:           "security_headers",
				ReferrerPolicy: &ReferrerPolicyConfig{Enabled: true, Policy: policy},
			}
			data, _ := json.Marshal(cfg)

			enforcer, err := New(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := enforcer.Enforce(next)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			got := w.Header().Get("Referrer-Policy")
			if got != policy {
				t.Errorf("expected %q, got %q", policy, got)
			}
		})
	}
}

// TestEnforce_ReferrerPolicy_Invalid verifies invalid policy is not set.
func TestEnforce_ReferrerPolicy_Invalid(t *testing.T) {
	cfg := Config{
		Type:           "security_headers",
		ReferrerPolicy: &ReferrerPolicyConfig{Enabled: true, Policy: "invalid-policy"},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	got := w.Header().Get("Referrer-Policy")
	if got != "" {
		t.Errorf("expected empty Referrer-Policy for invalid value, got %q", got)
	}
}

// TestEnforce_CSP_FromDirectives verifies CSP from structured directives.
func TestEnforce_CSP_FromDirectives(t *testing.T) {
	cfg := Config{
		Type: "security_headers",
		ContentSecurityPolicy: &CSPConfig{
			Enabled: true,
			Directives: &CSPDirectives{
				DefaultSrc: []string{"'self'"},
				ScriptSrc:  []string{"'self'", "https://cdn.example.com"},
				ImgSrc:     []string{"*"},
			},
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected Content-Security-Policy header to be set")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("expected CSP to contain default-src, got %q", csp)
	}
	if !strings.Contains(csp, "script-src") {
		t.Errorf("expected CSP to contain script-src, got %q", csp)
	}
}

// TestEnforce_CSP_ReportOnly verifies CSP report-only mode.
func TestEnforce_CSP_ReportOnly(t *testing.T) {
	cfg := Config{
		Type: "security_headers",
		ContentSecurityPolicy: &CSPConfig{
			Enabled:    true,
			Policy:     "default-src 'self'",
			ReportOnly: true,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Content-Security-Policy-Report-Only") == "" {
		t.Error("expected Content-Security-Policy-Report-Only header")
	}
}

// TestEnforce_MultipleHeaders verifies multiple security headers together.
func TestEnforce_MultipleHeaders(t *testing.T) {
	cfg := Config{
		Type:                    "security_headers",
		StrictTransportSecurity: &HSTSConfig{Enabled: true, MaxAge: 3600},
		XFrameOptions:          &XFrameOptionsConfig{Enabled: true, Value: "DENY"},
		XContentTypeOptions:    &XContentTypeOptionsConfig{Enabled: true, NoSniff: true},
		ReferrerPolicy:         &ReferrerPolicyConfig{Enabled: true, Policy: "no-referrer"},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Error("expected HSTS header")
	}
	if w.Header().Get("X-Frame-Options") == "" {
		t.Error("expected X-Frame-Options header")
	}
	if w.Header().Get("X-Content-Type-Options") == "" {
		t.Error("expected X-Content-Type-Options header")
	}
	if w.Header().Get("Referrer-Policy") == "" {
		t.Error("expected Referrer-Policy header")
	}
}

// TestCSPReportURI verifies the CSPReportURI interface method.
func TestCSPReportURI(t *testing.T) {
	tests := []struct {
		name     string
		config   *CSPConfig
		expected string
	}{
		{
			name:     "with report URI",
			config:   &CSPConfig{Enabled: true, ReportURI: "https://report.example.com"},
			expected: "https://report.example.com",
		},
		{
			name:     "no report URI",
			config:   &CSPConfig{Enabled: true},
			expected: "",
		},
		{
			name:     "disabled CSP",
			config:   &CSPConfig{Enabled: false, ReportURI: "https://report.example.com"},
			expected: "",
		},
		{
			name:     "nil CSP",
			config:   nil,
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Type:                  "security_headers",
				ContentSecurityPolicy: tc.config,
			}
			data, _ := json.Marshal(cfg)

			enforcer, err := New(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			sh := enforcer.(*secHeadersPolicy)
			got := sh.CSPReportURI()
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}
