package noop_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/modules/auth/noop"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	p, err := noop.New(json.RawMessage(`{"type":"noop"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestNew_EmptyJSON(t *testing.T) {
	p, err := noop.New(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestNew_NilJSON(t *testing.T) {
	p, err := noop.New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestType(t *testing.T) {
	p, _ := noop.New(json.RawMessage(`{}`))
	if p.Type() != "noop" {
		t.Errorf("Type() = %q, want %q", p.Type(), "noop")
	}
}

func TestWrap_PassesThrough(t *testing.T) {
	p, _ := noop.New(json.RawMessage(`{}`))

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
		t.Error("expected next handler to be called (noop should pass through)")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestWrap_ReturnsNextDirectly(t *testing.T) {
	p, _ := noop.New(json.RawMessage(`{}`))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := p.Wrap(next)

	// Noop Wrap should return the exact same handler.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAuth("noop")
	if !ok {
		t.Error("noop auth not registered in plugin registry")
	}
	_, ok = plugin.GetAuth("none")
	if !ok {
		t.Error("none auth not registered in plugin registry")
	}
}
