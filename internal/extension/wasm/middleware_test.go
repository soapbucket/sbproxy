package wasm

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestMiddleware_NoPlugins(t *testing.T) {
	m := NewMiddleware(nil, nil)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestMiddleware_HandleRequest_PassesHeaders(t *testing.T) {
	m := NewMiddleware(nil, nil) // no plugins, just verify passthrough

	var capturedHeaders http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Custom", "test-value")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedHeaders.Get("X-Custom") != "test-value" {
		t.Errorf("expected header X-Custom=%q, got %q", "test-value", capturedHeaders.Get("X-Custom"))
	}
}

func TestMiddleware_HandleRequest_PassesBody(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var capturedBody []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		capturedBody = body
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("request body")))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if string(capturedBody) != "request body" {
		t.Errorf("expected body %q, got %q", "request body", string(capturedBody))
	}
}

func TestMiddleware_HandleRequest_SetsRequestContext(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var rc *RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc = RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rc == nil {
		t.Fatal("expected RequestContext to be set in request context")
	}

	val, ok := rc.GetRequestHeader("accept")
	if !ok || val != "application/json" {
		t.Errorf("expected accept=%q, got %q", "application/json", val)
	}
}

func TestMiddleware_HandleResponse_NoPlugins(t *testing.T) {
	m := NewMiddleware(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := WithRequestContext(req.Context(), NewRequestContext())
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Test": []string{"value"}},
		Body:       io.NopCloser(bytes.NewReader([]byte("response body"))),
		Request:    req,
	}

	err := m.HandleResponse(resp)
	if err != nil {
		t.Fatalf("HandleResponse failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestMiddleware_HandleResponse_NilResponse(t *testing.T) {
	m := NewMiddleware(nil, nil)

	err := m.HandleResponse(nil)
	if err != nil {
		t.Fatalf("HandleResponse with nil should not error: %v", err)
	}
}

func TestNewMiddleware(t *testing.T) {
	m := NewMiddleware(nil, nil)
	if m == nil {
		t.Fatal("expected non-nil Middleware")
	}
	if m.plugins != nil {
		t.Error("expected nil plugins slice")
	}
}

func TestFilterOriginSecrets(t *testing.T) {
	all := map[string]string{
		"API_TOKEN": "token-123",
		"DB_PASS":   "db-pass",
	}

	t.Run("explicit subset", func(t *testing.T) {
		got := filterOriginSecrets(all, []string{"API_TOKEN"})
		if len(got) != 1 || got["API_TOKEN"] != "token-123" {
			t.Fatalf("expected filtered map with API_TOKEN only, got %#v", got)
		}
		if _, ok := got["DB_PASS"]; ok {
			t.Fatalf("expected DB_PASS to be filtered out, got %#v", got)
		}
	})

	t.Run("wildcard", func(t *testing.T) {
		got := filterOriginSecrets(all, []string{"*"})
		if len(got) != 2 {
			t.Fatalf("expected wildcard to include all secrets, got %#v", got)
		}
	})

	t.Run("empty grants", func(t *testing.T) {
		got := filterOriginSecrets(all, nil)
		if len(got) != 0 {
			t.Fatalf("expected empty grants to expose no secrets, got %#v", got)
		}
	})
}

func TestMiddleware_HandleRequest_NoPluginSecretsExposed(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var capturedRC *RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rd := reqctx.NewRequestData()
	rd.OriginCtx = &reqctx.OriginContext{
		Secrets: map[string]string{
			"API_TOKEN": "token-123",
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedRC == nil {
		t.Fatal("expected RequestContext to be set")
	}
	if len(capturedRC.OriginSecrets) != 0 {
		t.Fatalf("expected no secrets to be exposed without a plugin grant, got %#v", capturedRC.OriginSecrets)
	}
}
