package csrf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNew_ValidConfig verifies that a valid config creates an enforcer.
func TestNew_ValidConfig(t *testing.T) {
	cfg := Config{
		Type:   "csrf",
		Secret: "test-secret-key",
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

// TestNew_MissingSecret verifies that missing secret returns an error.
func TestNew_MissingSecret(t *testing.T) {
	cfg := Config{Type: "csrf"}
	data, _ := json.Marshal(cfg)

	_, err := New(data)
	if err == nil {
		t.Fatal("expected error for missing secret")
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
	cfg := Config{
		Type:   "csrf",
		Secret: "test-secret",
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cp := enforcer.(*csrfPolicy)
	if cp.Type() != "csrf" {
		t.Errorf("expected type 'csrf', got %q", cp.Type())
	}
}

// TestNew_Defaults verifies default values are set.
func TestNew_Defaults(t *testing.T) {
	cfg := Config{
		Type:   "csrf",
		Secret: "test-secret",
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cp := enforcer.(*csrfPolicy)
	if cp.cfg.CookieName != "_csrf" {
		t.Errorf("expected default cookie name '_csrf', got %q", cp.cfg.CookieName)
	}
	if cp.cfg.CookiePath != "/" {
		t.Errorf("expected default cookie path '/', got %q", cp.cfg.CookiePath)
	}
	if cp.cfg.HeaderName != "X-CSRF-Token" {
		t.Errorf("expected default header name 'X-CSRF-Token', got %q", cp.cfg.HeaderName)
	}
	if cp.cfg.TokenLength != 32 {
		t.Errorf("expected default token length 32, got %d", cp.cfg.TokenLength)
	}
	if len(cp.cfg.Methods) != 4 {
		t.Errorf("expected 4 default methods, got %d", len(cp.cfg.Methods))
	}
}

// TestEnforce_Disabled verifies that disabled policy passes through.
func TestEnforce_Disabled(t *testing.T) {
	cfg := Config{
		Type:     "csrf",
		Secret:   "test-secret",
		Disabled: true,
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

	req := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called when policy is disabled")
	}
}

// TestEnforce_GET_SetsCookie verifies that GET requests get a CSRF cookie.
func TestEnforce_GET_SetsCookie(t *testing.T) {
	cfg := Config{
		Type:   "csrf",
		Secret: "test-secret",
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
		t.Error("expected next handler to be called for GET")
	}

	// Check that a CSRF cookie was set
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "_csrf" {
			found = true
			if c.Value == "" {
				t.Error("CSRF cookie value should not be empty")
			}
		}
	}
	if !found {
		t.Error("expected CSRF cookie to be set")
	}
}

// TestEnforce_POST_MissingToken verifies POST without token is blocked.
func TestEnforce_POST_MissingToken(t *testing.T) {
	cfg := Config{
		Type:   "csrf",
		Secret: "test-secret",
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := enforcer.Enforce(next)

	// First GET to set the cookie
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getW := httptest.NewRecorder()
	handler.ServeHTTP(getW, getReq)

	// Now POST without the token
	postReq := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	// Copy the cookie from GET response
	for _, c := range getW.Result().Cookies() {
		postReq.AddCookie(c)
	}

	postW := httptest.NewRecorder()
	called = false
	handler.ServeHTTP(postW, postReq)

	if called {
		t.Error("expected next handler NOT to be called for POST without CSRF token")
	}
	if postW.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", postW.Code)
	}
}

// TestEnforce_ExemptPath verifies exempt paths bypass CSRF checks.
func TestEnforce_ExemptPath(t *testing.T) {
	cfg := Config{
		Type:        "csrf",
		Secret:      "test-secret",
		ExemptPaths: []string{"/api/webhook"},
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

	req := httptest.NewRequest(http.MethodPost, "/api/webhook", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called for exempt path")
	}
}

// TestParseSameSite verifies SameSite parsing.
func TestParseSameSite(t *testing.T) {
	tests := []struct {
		input    string
		expected http.SameSite
	}{
		{"strict", http.SameSiteStrictMode},
		{"Strict", http.SameSiteStrictMode},
		{"lax", http.SameSiteLaxMode},
		{"Lax", http.SameSiteLaxMode},
		{"none", http.SameSiteNoneMode},
		{"None", http.SameSiteNoneMode},
		{"invalid", http.SameSiteLaxMode},
		{"", http.SameSiteLaxMode},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseSameSite(tc.input)
			if got != tc.expected {
				t.Errorf("parseSameSite(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}
