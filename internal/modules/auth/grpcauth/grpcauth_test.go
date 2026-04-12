package grpcauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/modules/auth/grpcauth"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"type":"grpc_auth","address":"auth.example.com:50051"}`)
	p, err := grpcauth.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := grpcauth.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_MissingAddress(t *testing.T) {
	_, err := grpcauth.New(json.RawMessage(`{"type":"grpc_auth"}`))
	if err == nil {
		t.Fatal("expected error when address is missing")
	}
}

func TestType(t *testing.T) {
	p, _ := grpcauth.New(json.RawMessage(`{"type":"grpc_auth","address":"localhost:50051"}`))
	if p.Type() != "grpc_auth" {
		t.Errorf("Type() = %q, want %q", p.Type(), "grpc_auth")
	}
}

func TestWrap_AuthServerApproves(t *testing.T) {
	// Mock ext_authz server that returns gRPC OK (status code 0).
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":{"code":0}}`))
	}))
	defer authServer.Close()

	raw := json.RawMessage(`{"type":"grpc_auth","address":"` + authServer.Listener.Addr().String() + `"}`)
	p, err := grpcauth.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called when auth server approves")
	}
}

func TestWrap_AuthServerDenies(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":{"code":7},"denied_response":{"status":{"code":403},"body":"Access Denied"}}`))
	}))
	defer authServer.Close()

	raw := json.RawMessage(`{"type":"grpc_auth","address":"` + authServer.Listener.Addr().String() + `"}`)
	p, _ := grpcauth.New(raw)

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

func TestWrap_FailOpen(t *testing.T) {
	// Use an address that will fail to connect.
	raw := json.RawMessage(`{"type":"grpc_auth","address":"127.0.0.1:1","fail_open":true,"timeout":0.1}`)
	p, _ := grpcauth.New(raw)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called when fail_open is true and auth server is down")
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAuth("grpc_auth")
	if !ok {
		t.Error("grpc_auth not registered in plugin registry")
	}
}
