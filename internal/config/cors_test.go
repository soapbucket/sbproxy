package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORS_PreflightRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("preflight should not reach backend")
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.CORS = &CORSConfig{
		Enable:       true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET", "POST"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:       3600,
	}

	req := httptest.NewRequest("OPTIONS", "/api/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}

	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("expected origin https://example.com, got %s", rec.Header().Get("Access-Control-Allow-Origin"))
	}

	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected Access-Control-Allow-Methods header")
	}

	if rec.Header().Get("Access-Control-Max-Age") != "3600" {
		t.Errorf("expected max-age 3600, got %s", rec.Header().Get("Access-Control-Max-Age"))
	}
}

func TestCORS_PreflightRejectedOrigin(t *testing.T) {
	cfg := createTestProxyConfig(t, "http://localhost:9999")
	cfg.CORS = &CORSConfig{
		Enable:       true,
		AllowOrigins: []string{"https://allowed.com"},
	}

	req := httptest.NewRequest("OPTIONS", "/api/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for rejected origin, got %d", rec.Code)
	}
}

func TestCORS_WildcardOrigin(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.CORS = &CORSConfig{
		Enable:       true,
		AllowOrigins: []string{"*"},
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Origin", "https://any-origin.com")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected wildcard origin, got %s", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORS_CredentialsReflectOrigin(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.CORS = &CORSConfig{
		Enable:           true,
		AllowOrigins:     []string{"*"},
		AllowCredentials: true,
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Origin", "https://secure.com")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	// When credentials are allowed, origin must be reflected, not "*"
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://secure.com" {
		t.Errorf("expected reflected origin with credentials, got %s", rec.Header().Get("Access-Control-Allow-Origin"))
	}

	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Access-Control-Allow-Credentials: true")
	}
}

func TestCORS_NoCORSWithoutOrigin(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.CORS = &CORSConfig{
		Enable:       true,
		AllowOrigins: []string{"*"},
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	// No Origin header
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("should not set CORS headers without Origin")
	}
}
