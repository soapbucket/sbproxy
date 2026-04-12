package grpc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	grpcmod "github.com/soapbucket/sbproxy/internal/modules/action/grpc"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"url":"https://grpc.example.com:443"}`)
	h, err := grpcmod.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := grpcmod.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_MissingURL(t *testing.T) {
	_, err := grpcmod.New(json.RawMessage(`{"type":"grpc"}`))
	if err == nil {
		t.Fatal("expected error when url is missing")
	}
}

func TestNew_InvalidScheme(t *testing.T) {
	_, err := grpcmod.New(json.RawMessage(`{"url":"ftp://grpc.example.com"}`))
	if err == nil {
		t.Fatal("expected error for invalid scheme")
	}
}

func TestNew_GRPCScheme(t *testing.T) {
	h, err := grpcmod.New(json.RawMessage(`{"url":"grpc://grpc.example.com:443"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
}

func TestNew_GRPCSScheme(t *testing.T) {
	h, err := grpcmod.New(json.RawMessage(`{"url":"grpcs://grpc.example.com:443"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
}

func TestType(t *testing.T) {
	h, _ := grpcmod.New(json.RawMessage(`{"url":"https://grpc.example.com:443"}`))
	if h.Type() != "grpc" {
		t.Errorf("Type() = %q, want %q", h.Type(), "grpc")
	}
}

func TestServeHTTP_DirectNotSupported(t *testing.T) {
	h, _ := grpcmod.New(json.RawMessage(`{"url":"https://grpc.example.com:443"}`))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestTransport_NotNil(t *testing.T) {
	h, _ := grpcmod.New(json.RawMessage(`{"url":"https://grpc.example.com:443"}`))
	rpa, ok := h.(plugin.ReverseProxyAction)
	if !ok {
		t.Fatal("handler does not implement ReverseProxyAction")
	}
	if rpa.Transport() == nil {
		t.Error("Transport() should not return nil")
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("grpc")
	if !ok {
		t.Error("grpc action not registered in plugin registry")
	}
}
