package bearer_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/modules/auth/bearer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"type":"bearer_token","tokens":["tok-abc","tok-def"]}`)
	p, err := bearer.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := bearer.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestType(t *testing.T) {
	p, _ := bearer.New(json.RawMessage(`{"type":"bearer_token","tokens":["t1"]}`))
	if p.Type() != "bearer_token" {
		t.Errorf("Type() = %q, want %q", p.Type(), "bearer_token")
	}
}

func TestWrap_ValidToken(t *testing.T) {
	p, _ := bearer.New(json.RawMessage(`{"type":"bearer_token","tokens":["my-secret-token"]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called for valid token")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestWrap_InvalidToken(t *testing.T) {
	p, _ := bearer.New(json.RawMessage(`{"type":"bearer_token","tokens":["my-secret-token"]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called for invalid token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_MissingToken(t *testing.T) {
	p, _ := bearer.New(json.RawMessage(`{"type":"bearer_token","tokens":["tok"]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called when token is missing")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_CookieToken(t *testing.T) {
	p, _ := bearer.New(json.RawMessage(`{"type":"bearer_token","tokens":["cookie-tok"],"cookie_name":"auth_token"}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "cookie-tok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called with cookie token")
	}
}

func TestWrap_QueryParamToken(t *testing.T) {
	p, _ := bearer.New(json.RawMessage(`{"type":"bearer_token","tokens":["qtok"],"query_param":"token"}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/api?token=qtok", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called with query param token")
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAuth("bearer_token")
	if !ok {
		t.Error("bearer_token auth not registered in plugin registry")
	}
}
