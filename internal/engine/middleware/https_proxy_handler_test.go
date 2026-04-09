package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSProxyHandler_MethodNotAllowed(t *testing.T) {
	h := NewHTTPSProxyHandler(nil, "")
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestHTTPSProxyHandler_ProxyAuthRequiredWhenMissing(t *testing.T) {
	h := NewHTTPSProxyHandler(nil, "")
	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("expected %d, got %d", http.StatusProxyAuthRequired, rec.Code)
	}
	if got := rec.Header().Get("Proxy-Authenticate"); got == "" {
		t.Fatalf("expected Proxy-Authenticate header")
	}
}

func TestHTTPSProxyHandler_ProxyAuthRequiredOnInvalidBasic(t *testing.T) {
	h := NewHTTPSProxyHandler(nil, "")
	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)
	req.Header.Set("Proxy-Authorization", "Basic invalid@@@")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("expected %d, got %d", http.StatusProxyAuthRequired, rec.Code)
	}
}
