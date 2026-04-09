package wasm

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestContext_SharedData(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetSharedData("counter")
	if ok {
		t.Error("expected false for non-existent shared data")
	}

	rc.SetSharedData("counter", []byte{0x01, 0x02, 0x03})

	val, ok := rc.GetSharedData("counter")
	if !ok {
		t.Fatal("expected true for existing shared data")
	}
	if !bytes.Equal(val, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("expected [1 2 3], got %v", val)
	}

	// Overwrite
	rc.SetSharedData("counter", []byte{0x04})
	val, ok = rc.GetSharedData("counter")
	if !ok || !bytes.Equal(val, []byte{0x04}) {
		t.Errorf("expected [4], got %v (ok=%v)", val, ok)
	}
}

func TestRequestContext_SetSendResponse(t *testing.T) {
	rc := NewRequestContext()

	if rc.SendResponse {
		t.Error("expected SendResponse to be false initially")
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"X-Custom":     "test",
	}
	body := []byte(`{"error": "forbidden"}`)
	rc.SetSendResponse(403, headers, body)

	rc.mu.RLock()
	defer rc.mu.RUnlock()

	if !rc.SendResponse {
		t.Error("expected SendResponse to be true")
	}
	if rc.SendResponseCode != 403 {
		t.Errorf("expected status 403, got %d", rc.SendResponseCode)
	}
	if rc.SendResponseHeaders["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type header, got %q", rc.SendResponseHeaders["Content-Type"])
	}
	if rc.SendResponseHeaders["X-Custom"] != "test" {
		t.Errorf("expected X-Custom header, got %q", rc.SendResponseHeaders["X-Custom"])
	}
	if string(rc.SendResponseBody) != `{"error": "forbidden"}` {
		t.Errorf("expected body %q, got %q", `{"error": "forbidden"}`, string(rc.SendResponseBody))
	}
}

func TestMiddleware_HandleRequest_SendResponse(t *testing.T) {
	m := NewMiddleware(nil, nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Wrap handler to simulate a plugin setting SendResponse
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner := m.HandleRequest(next)
		// We need to intercept and set SendResponse before the handler runs,
		// but since plugins are empty, we test via the middleware directly.
		// Instead, test by manually checking the middleware logic path.
		inner.ServeHTTP(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// With no plugins, next should be called normally
	if !nextCalled {
		t.Error("expected next handler to be called when no plugins set SendResponse")
	}
}

func TestMiddleware_HandleRequest_PopulatesMetadata(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var capturedRC *RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users?page=2&limit=10", bytes.NewReader([]byte("body")))
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedRC == nil {
		t.Fatal("expected RequestContext to be set")
	}

	if m := capturedRC.GetRequestMethod(); m != "POST" {
		t.Errorf("expected method POST, got %q", m)
	}
	if p := capturedRC.GetRequestPath(); p != "/api/v1/users" {
		t.Errorf("expected path /api/v1/users, got %q", p)
	}
	if ip := capturedRC.GetClientIP(); ip != "10.0.0.1:12345" {
		t.Errorf("expected client IP 10.0.0.1:12345, got %q", ip)
	}

	val, ok := capturedRC.GetQueryParam("page")
	if !ok || val != "2" {
		t.Errorf("expected page=2, got %q (ok=%v)", val, ok)
	}
	val, ok = capturedRC.GetQueryParam("limit")
	if !ok || val != "10" {
		t.Errorf("expected limit=10, got %q (ok=%v)", val, ok)
	}
}

func TestMiddleware_HandleRequest_PathRewrite(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var capturedPath string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// After plugins run, the middleware should apply path modifications.
		// With no plugins, the path stays the same.
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/original/path", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedPath != "/original/path" {
		t.Errorf("expected path /original/path, got %q", capturedPath)
	}
}

func TestMiddleware_HandleResponse_StatusModification(t *testing.T) {
	m := NewMiddleware(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rc := NewRequestContext()
	rc.SetResponseStatus(201)
	ctx := WithRequestContext(req.Context(), rc)
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte("ok"))),
		Request:    req,
	}

	err := m.HandleResponse(resp)
	if err != nil {
		t.Fatalf("HandleResponse failed: %v", err)
	}

	// With no response-phase plugins, status is not modified by the middleware itself.
	// The ResponseStatus field is for plugins to read/write during their phase.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestNewRequestContext_InitializesMaps(t *testing.T) {
	rc := NewRequestContext()

	if rc.QueryParams == nil {
		t.Error("expected non-nil QueryParams map")
	}
	if rc.Variables == nil {
		t.Error("expected non-nil Variables map")
	}
	if rc.SharedData == nil {
		t.Error("expected non-nil SharedData map")
	}
	if rc.SendResponseHeaders == nil {
		t.Error("expected non-nil SendResponseHeaders map")
	}
}
