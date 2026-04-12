package noop_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	noopmod "github.com/soapbucket/sbproxy/internal/modules/action/noop"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew(t *testing.T) {
	h, err := noopmod.New(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
	if h.Type() != "noop" {
		t.Errorf("Type() = %q, want %q", h.Type(), "noop")
	}
}

func TestServeHTTP(t *testing.T) {
	h, _ := noopmod.New(json.RawMessage(`{}`))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("noop")
	if !ok {
		t.Error("noop action not registered")
	}
	_, ok = plugin.GetAction("")
	if !ok {
		t.Error("empty (TypeNone) action not registered")
	}
}
