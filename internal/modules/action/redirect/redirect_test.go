package redirect_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	redirectmod "github.com/soapbucket/sbproxy/internal/modules/action/redirect"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		code int
	}{
		{"301", `{"url":"https://example.com","status_code":301}`, 301},
		{"302", `{"url":"https://example.com","status_code":302}`, 302},
		{"307", `{"url":"https://example.com","status_code":307}`, 307},
		{"308", `{"url":"https://example.com","status_code":308}`, 308},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := redirectmod.New(json.RawMessage(tc.raw))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if h.Type() != "redirect" {
				t.Errorf("Type() = %q, want redirect", h.Type())
			}

			req := httptest.NewRequest(http.MethodGet, "/old", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.code {
				t.Errorf("status = %d, want %d", rec.Code, tc.code)
			}
			if loc := rec.Header().Get("Location"); loc != "https://example.com" {
				t.Errorf("Location = %q, want https://example.com", loc)
			}
		})
	}
}

func TestNew_InvalidStatusCode(t *testing.T) {
	_, err := redirectmod.New(json.RawMessage(`{"url":"https://example.com","status_code":200}`))
	if err == nil {
		t.Error("expected error for status 200, got nil")
	}
}

func TestNew_MissingURL(t *testing.T) {
	_, err := redirectmod.New(json.RawMessage(`{"status_code":301}`))
	if err == nil {
		t.Error("expected error for missing url")
	}
}

func TestServeHTTP_PreserveQuery(t *testing.T) {
	h, err := redirectmod.New(json.RawMessage(`{"url":"https://example.com","status_code":301,"preserve_query":true}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/path?foo=bar", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	if loc != "https://example.com?foo=bar" {
		t.Errorf("Location = %q, want https://example.com?foo=bar", loc)
	}
}

func TestServeHTTP_StripBasePath(t *testing.T) {
	h, err := redirectmod.New(json.RawMessage(`{"url":"https://new.example.com","status_code":301,"strip_base_path":true}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/foo/bar", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	if loc != "https://new.example.com/foo/bar" {
		t.Errorf("Location = %q, want https://new.example.com/foo/bar", loc)
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("redirect")
	if !ok {
		t.Error("redirect action not registered")
	}
}
