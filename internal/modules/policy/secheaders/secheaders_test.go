package secheaders

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustBuild(t *testing.T, cfg Config) *secHeadersPolicy {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return enforcer.(*secHeadersPolicy)
}

func runEnforce(t *testing.T, p *secHeadersPolicy, path string) *httptest.ResponseRecorder {
	t.Helper()
	handler := p.Enforce(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestNew_ValidConfig(t *testing.T) {
	cfg := Config{
		Type: "security_headers",
		Headers: []SecurityHeader{
			{Name: "X-Frame-Options", Value: "DENY"},
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

func TestNew_InvalidJSON(t *testing.T) {
	if _, err := New(json.RawMessage(`{invalid`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestType(t *testing.T) {
	p := mustBuild(t, Config{Type: "security_headers"})
	if p.Type() != "security_headers" {
		t.Errorf("expected type 'security_headers', got %q", p.Type())
	}
}

func TestEnforce_Disabled(t *testing.T) {
	p := mustBuild(t, Config{
		Type:     "security_headers",
		Disabled: true,
		Headers: []SecurityHeader{
			{Name: "Strict-Transport-Security", Value: "max-age=31536000"},
		},
	})
	w := runEnforce(t, p, "/")
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("expected no HSTS header when policy is disabled")
	}
}

func TestEnforce_HeadersArray(t *testing.T) {
	p := mustBuild(t, Config{
		Type: "security_headers",
		Headers: []SecurityHeader{
			{Name: "Strict-Transport-Security", Value: "max-age=31536000; includeSubDomains"},
			{Name: "X-Frame-Options", Value: "DENY"},
			{Name: "X-Content-Type-Options", Value: "nosniff"},
			{Name: "Referrer-Policy", Value: "strict-origin-when-cross-origin"},
		},
	})
	w := runEnforce(t, p, "/")
	h := w.Header()

	cases := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
	for name, want := range cases {
		if got := h.Get(name); got != want {
			t.Errorf("%s: expected %q, got %q", name, want, got)
		}
	}
}

func TestEnforce_HeadersArray_CanonicalizesName(t *testing.T) {
	// Lowercase input name should be canonicalized on the response.
	p := mustBuild(t, Config{
		Type: "security_headers",
		Headers: []SecurityHeader{
			{Name: "x-frame-options", Value: "DENY"},
		},
	})
	w := runEnforce(t, p, "/")
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("expected DENY, got %q", got)
	}
}

func TestEnforce_CSP_Simple_FromHeaders(t *testing.T) {
	p := mustBuild(t, Config{
		Type: "security_headers",
		Headers: []SecurityHeader{
			{Name: "Content-Security-Policy", Value: "default-src 'self'"},
		},
	})
	w := runEnforce(t, p, "/")
	if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Errorf("expected simple CSP, got %q", got)
	}
}

func TestCSP_UnmarshalString(t *testing.T) {
	// The CSP block accepts a plain string as a shorthand for {"policy": "<s>"}.
	raw := []byte(`{"type":"security_headers","content_security_policy":"default-src 'self'"}`)
	enforcer, err := New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := enforcer.(*secHeadersPolicy)
	if p.cfg.ContentSecurityPolicy == nil {
		t.Fatal("expected CSP block")
	}
	if p.cfg.ContentSecurityPolicy.Policy != "default-src 'self'" {
		t.Errorf("expected policy string, got %q", p.cfg.ContentSecurityPolicy.Policy)
	}

	w := runEnforce(t, p, "/")
	if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Errorf("expected simple CSP emitted, got %q", got)
	}
}

func TestEnforce_CSP_WithNonce(t *testing.T) {
	p := mustBuild(t, Config{
		Type: "security_headers",
		ContentSecurityPolicy: &ContentSecurityPolicy{
			Policy:      "default-src 'self'; script-src 'self'",
			EnableNonce: true,
		},
	})
	w := runEnforce(t, p, "/")
	nonce := w.Header().Get("X-CSP-Nonce")
	if nonce == "" {
		t.Fatal("expected X-CSP-Nonce header to be set")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'nonce-"+nonce+"'") {
		t.Errorf("expected nonce %q injected into script-src; got %q", nonce, csp)
	}
}

func TestEnforce_CSP_ReportOnly(t *testing.T) {
	p := mustBuild(t, Config{
		Type: "security_headers",
		ContentSecurityPolicy: &ContentSecurityPolicy{
			Policy:     "default-src 'self'",
			ReportOnly: true,
			ReportURI:  "/csp-report",
		},
	})
	w := runEnforce(t, p, "/")
	h := w.Header()
	if got := h.Get("Content-Security-Policy-Report-Only"); !strings.Contains(got, "report-uri /csp-report") {
		t.Errorf("expected report-only CSP with report-uri, got %q", got)
	}
	if h.Get("Content-Security-Policy") != "" {
		t.Error("expected no enforcing CSP when report_only=true")
	}
}

func TestEnforce_CSP_DynamicRoutes(t *testing.T) {
	p := mustBuild(t, Config{
		Type: "security_headers",
		ContentSecurityPolicy: &ContentSecurityPolicy{
			Policy: "default-src 'self'",
			DynamicRoutes: map[string]*ContentSecurityPolicy{
				"/admin":       {Policy: "default-src 'self' admin.example.com"},
				"/admin/users": {Policy: "default-src 'self' admin.example.com users.example.com"},
			},
		},
	})

	cases := map[string]string{
		"/":               "default-src 'self'",
		"/admin/settings": "default-src 'self' admin.example.com",
		"/admin/users/42": "default-src 'self' admin.example.com users.example.com",
	}
	for path, want := range cases {
		w := runEnforce(t, p, path)
		if got := w.Header().Get("Content-Security-Policy"); got != want {
			t.Errorf("%s: expected %q, got %q", path, want, got)
		}
	}
}

func TestEnforce_CSP_BlockOverridesHeadersList(t *testing.T) {
	// When the CSP block requires per-request processing, any
	// Content-Security-Policy entry in `headers` must be skipped.
	p := mustBuild(t, Config{
		Type: "security_headers",
		Headers: []SecurityHeader{
			{Name: "Content-Security-Policy", Value: "ignored-value"},
			{Name: "X-Frame-Options", Value: "DENY"},
		},
		ContentSecurityPolicy: &ContentSecurityPolicy{
			Policy:      "default-src 'self'",
			EnableNonce: true,
		},
	})
	w := runEnforce(t, p, "/")
	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "ignored-value") {
		t.Errorf("headers[] CSP should be skipped when block owns it, got %q", csp)
	}
	if !strings.HasPrefix(csp, "default-src 'self'") {
		t.Errorf("expected block-authored CSP, got %q", csp)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("non-CSP headers from list should still apply")
	}
}

func TestCSPReportURI(t *testing.T) {
	cases := []struct {
		name string
		csp  *ContentSecurityPolicy
		want string
	}{
		{"with report URI", &ContentSecurityPolicy{ReportURI: "https://report.example.com"}, "https://report.example.com"},
		{"no report URI", &ContentSecurityPolicy{}, ""},
		{"nil CSP", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustBuild(t, Config{
				Type:                  "security_headers",
				ContentSecurityPolicy: tc.csp,
			})
			if got := p.CSPReportURI(); got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestInjectNonceIntoPolicy_PreservesExisting(t *testing.T) {
	out := injectNonceIntoPolicy("script-src 'self' 'nonce-fixed'; style-src 'self'", "new")
	// script-src already has a nonce, must not be doubled.
	if strings.Contains(out, "'nonce-new'") && strings.Count(out, "'nonce-") != 2 {
		t.Errorf("unexpected nonce injection: %q", out)
	}
	// style-src had no nonce, should now have the new one.
	if !strings.Contains(out, "style-src 'self' 'nonce-new'") {
		t.Errorf("expected nonce on style-src, got %q", out)
	}
}
