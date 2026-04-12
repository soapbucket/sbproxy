package static_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	staticmod "github.com/soapbucket/sbproxy/internal/modules/action/static"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_DefaultStatus(t *testing.T) {
	h, err := staticmod.New(json.RawMessage(`{"body":"hello"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "hello" {
		t.Errorf("body = %q, want hello", rec.Body.String())
	}
}

func TestNew_CustomStatusAndContentType(t *testing.T) {
	h, err := staticmod.New(json.RawMessage(`{"status_code":404,"content_type":"application/json","body":"{}"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestNew_Base64Body(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("binary data"))
	h, err := staticmod.New(json.RawMessage(`{"body_base64":"` + encoded + `"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "binary data" {
		t.Errorf("body = %q, want binary data", rec.Body.String())
	}
}

func TestNew_JSONBody(t *testing.T) {
	h, err := staticmod.New(json.RawMessage(`{"json_body":{"key":"value"}}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if rec.Body.String() != `{"key":"value"}` {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestNew_CustomHeaders(t *testing.T) {
	h, err := staticmod.New(json.RawMessage(`{"body":"ok","headers":{"X-Foo":"bar"}}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if v := rec.Header().Get("X-Foo"); v != "bar" {
		t.Errorf("X-Foo = %q, want bar", v)
	}
}

func TestNew_InvalidBase64(t *testing.T) {
	_, err := staticmod.New(json.RawMessage(`{"body_base64":"!!!bad!!!"}`))
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestType(t *testing.T) {
	h, _ := staticmod.New(json.RawMessage(`{}`))
	if h.Type() != "static" {
		t.Errorf("Type() = %q, want static", h.Type())
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("static")
	if !ok {
		t.Error("static action not registered")
	}
}
