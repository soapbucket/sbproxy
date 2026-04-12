package beacon_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	beaconmod "github.com/soapbucket/sbproxy/internal/modules/action/beacon"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_EmptyGIF(t *testing.T) {
	h, err := beaconmod.New(json.RawMessage(`{"type":"beacon","empty_gif":true}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h.Type() != "beacon" {
		t.Errorf("Type() = %q, want beacon", h.Type())
	}

	req := httptest.NewRequest(http.MethodGet, "/pixel.gif", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/gif" {
		t.Errorf("Content-Type = %q, want image/gif", ct)
	}
	// Verify it's a valid base64 GIF.
	if rec.Body.Len() == 0 {
		t.Error("expected non-empty body for empty_gif")
	}
}

func TestNew_CustomBase64Body(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("hello"))
	raw := json.RawMessage(`{"type":"beacon","body_base64":"` + encoded + `","content_type":"text/plain","status_code":200}`)
	h, err := beaconmod.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "hello" {
		t.Errorf("body = %q, want hello", rec.Body.String())
	}
}

func TestNew_InvalidBase64(t *testing.T) {
	_, err := beaconmod.New(json.RawMessage(`{"body_base64":"!!!not-base64!!!"}`))
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestNew_TextBody(t *testing.T) {
	h, err := beaconmod.New(json.RawMessage(`{"body":"pong","status_code":202}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	if rec.Body.String() != "pong" {
		t.Errorf("body = %q, want pong", rec.Body.String())
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("beacon")
	if !ok {
		t.Error("beacon action not registered")
	}
}
