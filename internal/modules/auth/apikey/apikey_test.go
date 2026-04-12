package apikey_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/modules/auth/apikey"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"type":"api_key","api_keys":["key-abc","key-def"]}`)
	p, err := apikey.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := apikey.New(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_EmptyKeys(t *testing.T) {
	p, err := apikey.New(json.RawMessage(`{"type":"api_key","api_keys":[]}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestType(t *testing.T) {
	p, err := apikey.New(json.RawMessage(`{"type":"api_key","api_keys":["k1"]}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Type() != "api_key" {
		t.Errorf("Type() = %q, want %q", p.Type(), "api_key")
	}
}

func TestWrap_ValidKey(t *testing.T) {
	p, _ := apikey.New(json.RawMessage(`{"type":"api_key","api_keys":["aK7mR9pL2xQ4nB3"]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-API-Key", "aK7mR9pL2xQ4nB3")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called for valid key")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestWrap_InvalidKey(t *testing.T) {
	p, _ := apikey.New(json.RawMessage(`{"type":"api_key","api_keys":["aK7mR9pL2xQ4nB3"]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called for invalid key")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_MissingKey(t *testing.T) {
	p, _ := apikey.New(json.RawMessage(`{"type":"api_key","api_keys":["aK7mR9pL2xQ4nB3"]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called when key is missing")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_CustomHeaderName(t *testing.T) {
	p, _ := apikey.New(json.RawMessage(`{"type":"api_key","api_keys":["mykey"],"header_name":"X-Custom-Auth"}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Custom-Auth", "mykey")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called with custom header name")
	}
}

func TestWrap_QueryParam(t *testing.T) {
	p, _ := apikey.New(json.RawMessage(`{"type":"api_key","api_keys":["qkey"],"query_param":"api_key"}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/api?api_key=qkey", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called with query param key")
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAuth("api_key")
	if !ok {
		t.Error("api_key auth not registered in plugin registry")
	}
}
