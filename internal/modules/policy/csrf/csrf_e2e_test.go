package csrf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCSRF_E2E_POSTWithoutToken_Rejected verifies POST without a token is rejected with 403.
func TestCSRF_E2E_POSTWithoutToken_Rejected(t *testing.T) {
	cfg := Config{
		Type:   "csrf",
		Secret: "eR7tK3mW9pL2vX5qJ8",
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should NOT be called when CSRF token is missing")
		w.WriteHeader(http.StatusOK)
	})
	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodPost, "/api/submit", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", w.Code)
	}
}

// TestCSRF_E2E_GETSetsCookie verifies GET request sets the CSRF cookie.
func TestCSRF_E2E_GETSetsCookie(t *testing.T) {
	cfg := Config{
		Type:       "csrf",
		Secret:     "eR7tK3mW9pL2vX5qJ8",
		CookieName: "_csrf_test",
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called for GET request")
	}

	cookies := w.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "_csrf_test" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected CSRF cookie to be set on GET request")
	}
	if csrfCookie.Value == "" {
		t.Error("CSRF cookie value should not be empty")
	}
	if csrfCookie.Path != "/" {
		t.Errorf("expected cookie path '/', got %q", csrfCookie.Path)
	}
}

// TestCSRF_E2E_POSTWithValidToken_Passes verifies POST with a valid token from cookie passes.
func TestCSRF_E2E_POSTWithValidToken_Passes(t *testing.T) {
	cfg := Config{
		Type:   "csrf",
		Secret: "eR7tK3mW9pL2vX5qJ8",
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := enforcer.Enforce(next)

	// Step 1: GET to obtain the CSRF cookie.
	getReq := httptest.NewRequest(http.MethodGet, "/page", nil)
	getW := httptest.NewRecorder()
	handler.ServeHTTP(getW, getReq)

	cookies := getW.Result().Cookies()
	var csrfToken string
	for _, c := range cookies {
		if c.Name == "_csrf" {
			csrfToken = c.Value
			break
		}
	}
	if csrfToken == "" {
		t.Fatal("CSRF cookie not set on GET")
	}

	// Step 2: POST with the token in the header and the cookie.
	nextCalled = false
	postReq := httptest.NewRequest(http.MethodPost, "/api/submit", nil)
	postReq.AddCookie(&http.Cookie{Name: "_csrf", Value: csrfToken})
	postReq.Header.Set("X-CSRF-Token", csrfToken)

	postW := httptest.NewRecorder()
	handler.ServeHTTP(postW, postReq)

	if !nextCalled {
		t.Error("expected next handler to be called when valid CSRF token is provided")
	}
	if postW.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", postW.Code)
	}
}

// TestCSRF_E2E_ExemptPaths_BypassCSRF verifies exempt paths bypass CSRF checks.
func TestCSRF_E2E_ExemptPaths_BypassCSRF(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		exempt bool
	}{
		{name: "exempt webhook path", path: "/api/webhook", exempt: true},
		{name: "exempt health path", path: "/healthz", exempt: true},
		{name: "non-exempt api path", path: "/api/data", exempt: false},
		{name: "non-exempt root path", path: "/", exempt: false},
	}

	cfg := Config{
		Type:        "csrf",
		Secret:      "eR7tK3mW9pL2vX5qJ8",
		ExemptPaths: []string{"/api/webhook", "/healthz"},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})
			handler := enforcer.Enforce(next)

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if tc.exempt && !called {
				t.Errorf("exempt path %s: expected next handler to be called", tc.path)
			}
			if !tc.exempt && called {
				t.Errorf("non-exempt path %s: expected next handler NOT to be called without token", tc.path)
			}
			if !tc.exempt && w.Code != http.StatusForbidden {
				t.Errorf("non-exempt path %s: expected 403, got %d", tc.path, w.Code)
			}
		})
	}
}

// TestCSRF_E2E_ProtectedMethods verifies that only configured methods require CSRF tokens.
func TestCSRF_E2E_ProtectedMethods(t *testing.T) {
	tests := []struct {
		method    string
		protected bool
	}{
		{http.MethodGet, false},
		{http.MethodHead, false},
		{http.MethodOptions, false},
		{http.MethodPost, true},
		{http.MethodPut, true},
		{http.MethodDelete, true},
		{http.MethodPatch, true},
	}

	cfg := Config{
		Type:   "csrf",
		Secret: "eR7tK3mW9pL2vX5qJ8",
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})
			handler := enforcer.Enforce(next)

			req := httptest.NewRequest(tc.method, "/api/data", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if tc.protected && called {
				t.Errorf("method %s should be protected (require CSRF token)", tc.method)
			}
			if !tc.protected && !called {
				t.Errorf("method %s should NOT be protected", tc.method)
			}
		})
	}
}

// TestCSRF_E2E_InvalidToken_Rejected verifies POST with an invalid token is rejected.
func TestCSRF_E2E_InvalidToken_Rejected(t *testing.T) {
	cfg := Config{
		Type:   "csrf",
		Secret: "eR7tK3mW9pL2vX5qJ8",
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	postCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalled = true
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := enforcer.Enforce(next)

	// Step 1: GET to obtain the CSRF cookie.
	getReq := httptest.NewRequest(http.MethodGet, "/page", nil)
	getW := httptest.NewRecorder()
	handler.ServeHTTP(getW, getReq)

	cookies := getW.Result().Cookies()
	var csrfToken string
	for _, c := range cookies {
		if c.Name == "_csrf" {
			csrfToken = c.Value
			break
		}
	}
	if csrfToken == "" {
		t.Fatal("CSRF cookie not set on GET")
	}

	// Step 2: POST with a different/invalid token.
	postReq := httptest.NewRequest(http.MethodPost, "/api/submit", nil)
	postReq.AddCookie(&http.Cookie{Name: "_csrf", Value: csrfToken})
	postReq.Header.Set("X-CSRF-Token", "totally-wrong-token")

	postW := httptest.NewRecorder()
	handler.ServeHTTP(postW, postReq)

	if postW.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid token, got %d", postW.Code)
	}
	if postCalled {
		t.Error("next handler should NOT be called for POST with invalid token")
	}
}

// TestCSRF_E2E_CustomMethods verifies custom method configuration.
func TestCSRF_E2E_CustomMethods(t *testing.T) {
	cfg := Config{
		Type:    "csrf",
		Secret:  "eR7tK3mW9pL2vX5qJ8",
		Methods: []string{"POST"}, // Only POST is protected, not PUT/DELETE/PATCH
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	tests := []struct {
		method    string
		protected bool
	}{
		{http.MethodPost, true},
		{http.MethodPut, false},    // not in custom methods list
		{http.MethodDelete, false}, // not in custom methods list
		{http.MethodGet, false},
	}

	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})
			handler := enforcer.Enforce(next)

			req := httptest.NewRequest(tc.method, "/api/data", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if tc.protected && called {
				t.Errorf("%s should be protected", tc.method)
			}
			if !tc.protected && !called {
				t.Errorf("%s should NOT be protected", tc.method)
			}
		})
	}
}
