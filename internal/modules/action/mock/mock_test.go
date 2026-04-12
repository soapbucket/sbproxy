package mock_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mockmod "github.com/soapbucket/sbproxy/internal/modules/action/mock"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_DefaultStatus(t *testing.T) {
	h, err := mockmod.New(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestNew_CustomStatus(t *testing.T) {
	h, err := mockmod.New(json.RawMessage(`{"status_code":503,"body":"unavailable"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if rec.Body.String() != "unavailable" {
		t.Errorf("body = %q, want unavailable", rec.Body.String())
	}
}

func TestNew_CustomHeaders(t *testing.T) {
	h, err := mockmod.New(json.RawMessage(`{"headers":{"X-Mock":"yes"}}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if v := rec.Header().Get("X-Mock"); v != "yes" {
		t.Errorf("X-Mock = %q, want yes", v)
	}
}

func TestNew_Delay(t *testing.T) {
	h, err := mockmod.New(json.RawMessage(`{"delay":"50ms"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Errorf("delay too short: %v", elapsed)
	}
}

func TestNew_DelayContextCancellation(t *testing.T) {
	h, err := mockmod.New(json.RawMessage(`{"delay":"5s"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("expected non-200 on cancellation")
	}
}

func TestType(t *testing.T) {
	h, _ := mockmod.New(json.RawMessage(`{}`))
	if h.Type() != "mock" {
		t.Errorf("Type() = %q, want mock", h.Type())
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("mock")
	if !ok {
		t.Error("mock action not registered")
	}
}
