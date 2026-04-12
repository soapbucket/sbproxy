package basicauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/modules/auth/basicauth"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"type":"basic_auth","users":[{"username":"admin","password":"pass123"}]}`)
	p, err := basicauth.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := basicauth.New(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestType(t *testing.T) {
	p, _ := basicauth.New(json.RawMessage(`{"type":"basic_auth","users":[]}`))
	if p.Type() != "basic_auth" {
		t.Errorf("Type() = %q, want %q", p.Type(), "basic_auth")
	}
}

func TestWrap_ValidCredentials(t *testing.T) {
	p, _ := basicauth.New(json.RawMessage(`{"type":"basic_auth","users":[{"username":"admin","password":"secret"}]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "secret")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called for valid credentials")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestWrap_InvalidPassword(t *testing.T) {
	p, _ := basicauth.New(json.RawMessage(`{"type":"basic_auth","users":[{"username":"admin","password":"secret"}]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called for invalid password")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_MissingCredentials(t *testing.T) {
	p, _ := basicauth.New(json.RawMessage(`{"type":"basic_auth","users":[{"username":"admin","password":"secret"}]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called when credentials are missing")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	// Should send WWW-Authenticate challenge.
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header in response")
	}
}

func TestWrap_UnknownUser(t *testing.T) {
	p, _ := basicauth.New(json.RawMessage(`{"type":"basic_auth","users":[{"username":"admin","password":"secret"}]}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("unknown", "secret")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called for unknown user")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAuth("basic_auth")
	if !ok {
		t.Error("basic_auth auth not registered in plugin registry")
	}
}
