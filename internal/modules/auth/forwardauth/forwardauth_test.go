package forwardauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/modules/auth/forwardauth"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"type":"forward","url":"https://auth.example.com/check"}`)
	p, err := forwardauth.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := forwardauth.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_MissingURL(t *testing.T) {
	_, err := forwardauth.New(json.RawMessage(`{"type":"forward"}`))
	if err == nil {
		t.Fatal("expected error when url is missing")
	}
}

func TestType(t *testing.T) {
	p, _ := forwardauth.New(json.RawMessage(`{"type":"forward","url":"https://auth.example.com/check"}`))
	if p.Type() != "forward" {
		t.Errorf("Type() = %q, want %q", p.Type(), "forward")
	}
}

func TestWrap_AuthServerApproves(t *testing.T) {
	// Set up a mock auth server that returns 200.
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify forwarded headers.
		if r.Header.Get("X-Forwarded-Method") == "" {
			t.Error("expected X-Forwarded-Method header")
		}
		if r.Header.Get("X-Forwarded-Host") == "" {
			t.Error("expected X-Forwarded-Host header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	raw := json.RawMessage(`{"type":"forward","url":"` + authServer.URL + `"}`)
	p, err := forwardauth.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called when auth server approves")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestWrap_AuthServerDenies(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer authServer.Close()

	raw := json.RawMessage(`{"type":"forward","url":"` + authServer.URL + `"}`)
	p, _ := forwardauth.New(raw)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called when auth server denies")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestWrap_TrustHeaders(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-User", "admin")
		w.Header().Set("X-Auth-Role", "superuser")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	raw := json.RawMessage(`{"type":"forward","url":"` + authServer.URL + `","trust_headers":["X-Auth-User","X-Auth-Role"]}`)
	p, _ := forwardauth.New(raw)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-User") != "admin" {
			t.Errorf("expected X-Auth-User=admin, got %q", r.Header.Get("X-Auth-User"))
		}
		if r.Header.Get("X-Auth-Role") != "superuser" {
			t.Errorf("expected X-Auth-Role=superuser, got %q", r.Header.Get("X-Auth-Role"))
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAuth("forward")
	if !ok {
		t.Error("forward auth not registered in plugin registry")
	}
}
