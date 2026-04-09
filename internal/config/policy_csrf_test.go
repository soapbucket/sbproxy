package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFPolicy_Basic(t *testing.T) {
	data := []byte(`{
		"type": "csrf",
		"secret": "test-secret-key-12345678901234567890"
	}`)

	policy, err := NewCSRFPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create CSRF policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// Test GET request (should allow and set cookie)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Next handler should have been called for GET request")
	}

	// Check that CSRF cookie was set
	cookies := rec.Result().Cookies()
	csrfCookieFound := false
	for _, cookie := range cookies {
		if cookie.Name == "_csrf" {
			csrfCookieFound = true
			if cookie.Value == "" {
				t.Error("CSRF cookie should have a value")
			}
			break
		}
	}
	if !csrfCookieFound {
		t.Error("CSRF cookie should have been set")
	}
}

func TestCSRFPolicy_POSTWithoutToken(t *testing.T) {
	data := []byte(`{
		"type": "csrf",
		"secret": "test-secret-key-12345678901234567890"
	}`)

	policy, err := NewCSRFPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create CSRF policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// Test POST request without token (should be blocked)
	req := httptest.NewRequest("POST", "/test", nil)
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Next handler should not have been called for POST without token")
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestCSRFPolicy_POSTWithToken(t *testing.T) {
	data := []byte(`{
		"type": "csrf",
		"secret": "test-secret-key-12345678901234567890"
	}`)

	policy, err := NewCSRFPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create CSRF policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// First, get a token via GET request
	getReq := httptest.NewRequest("GET", "/test", nil)
	getRec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(getRec, getReq)

	// Extract token from cookie
	var token string
	cookies := getRec.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "_csrf" {
			token = cookie.Value
			break
		}
	}

	if token == "" {
		t.Fatal("Failed to get CSRF token from cookie")
	}

	// Now test POST with token in header
	postReq := httptest.NewRequest("POST", "/test", nil)
	postReq.Header.Set("X-CSRF-Token", token)
	postReq.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	postRec := httptest.NewRecorder()

	nextCalled := false
	next2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler2 := policy.Apply(next2)
	handler2.ServeHTTP(postRec, postReq)

	if !nextCalled {
		t.Error("Next handler should have been called for POST with valid token")
	}

	if postRec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, postRec.Code)
	}
}

func TestCSRFPolicy_ExemptPaths(t *testing.T) {
	data := []byte(`{
		"type": "csrf",
		"secret": "test-secret-key-12345678901234567890",
		"exempt_paths": ["/webhook", "/api/public"]
	}`)

	policy, err := NewCSRFPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create CSRF policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// Test POST to exempt path (should allow)
	req := httptest.NewRequest("POST", "/webhook", nil)
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Next handler should have been called for exempt path")
	}
}

func TestCSRFPolicy_InvalidSecret(t *testing.T) {
	data := []byte(`{
		"type": "csrf"
	}`)

	_, err := NewCSRFPolicy(data)
	if err == nil {
		t.Error("Expected error when secret is missing")
	}
}

