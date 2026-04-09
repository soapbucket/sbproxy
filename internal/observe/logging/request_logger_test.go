package logging

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// mockHijacker is a mock response writer that implements http.Hijacker
type mockHijacker struct {
	http.ResponseWriter
	hijacked bool
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	m.hijacked = true
	// Return a mock connection for testing
	server, client := net.Pipe()
	go func() { server.Close() }()
	rw := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	return client, rw, nil
}

// nonHijacker is a response writer that does not implement http.Hijacker
type nonHijacker struct {
	http.ResponseWriter
}

func TestResponseWriter_Hijack(t *testing.T) {
	tests := []struct {
		name       string
		underlying http.ResponseWriter
		wantErr    bool
	}{
		{
			name:       "underlying implements Hijacker",
			underlying: &mockHijacker{ResponseWriter: httptest.NewRecorder()},
			wantErr:    false,
		},
		{
			name:       "underlying does not implement Hijacker",
			underlying: &nonHijacker{ResponseWriter: httptest.NewRecorder()},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := &responseWriter{
				ResponseWriter: tt.underlying,
				statusCode:     http.StatusOK,
			}

			conn, brw, err := rw.Hijack()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				if conn != nil {
					t.Error("expected nil connection")
					conn.Close()
				}
				if brw != nil {
					t.Error("expected nil bufio.ReadWriter")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if conn == nil {
					t.Error("expected non-nil connection")
				} else {
					conn.Close()
				}
				if brw == nil {
					t.Error("expected non-nil bufio.ReadWriter")
				}

				// Verify the underlying hijacker was called
				if mh, ok := tt.underlying.(*mockHijacker); ok {
					if !mh.hijacked {
						t.Error("underlying Hijack() was not called")
					}
				}
			}
		})
	}
}

func TestResponseWriter_ImplementsHijacker(t *testing.T) {
	rw := &responseWriter{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusOK,
	}

	// Verify that responseWriter implements http.Hijacker
	_, ok := interface{}(rw).(http.Hijacker)
	if !ok {
		t.Error("responseWriter does not implement http.Hijacker")
	}
}

func TestResponseWriter_Flush(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: recorder,
		statusCode:     http.StatusOK,
	}

	// Should not panic even if underlying doesn't flush
	rw.Flush()
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: recorder,
		statusCode:     200,
	}

	rw.WriteHeader(http.StatusNotFound)

	if rw.statusCode != http.StatusNotFound {
		t.Errorf("expected status code %d, got %d", http.StatusNotFound, rw.statusCode)
	}
	if !rw.headerWritten {
		t.Error("expected headerWritten to be true")
	}
}

func TestResponseWriter_Write(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: recorder,
		statusCode:     200,
	}

	data := []byte("hello world")
	n, err := rw.Write(data)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}
	if rw.bytesWritten != int64(len(data)) {
		t.Errorf("expected bytesWritten=%d, got %d", len(data), rw.bytesWritten)
	}
	if !rw.headerWritten {
		t.Error("expected headerWritten to be true after Write")
	}
}

func TestResponseWriter_WriteHeaderSkipsHeaderCloneWhenDisabled(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.Header().Set("Content-Type", "text/plain")
	rw := &responseWriter{
		ResponseWriter: recorder,
		statusCode:     200,
		captureHeaders: false,
	}

	rw.WriteHeader(http.StatusAccepted)

	if rw.headers != nil {
		t.Fatal("expected response headers to remain nil when capture is disabled")
	}
}

func TestResponseWriter_WriteHeaderClonesHeadersWhenEnabled(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.Header().Set("Content-Type", "text/plain")
	rw := &responseWriter{
		ResponseWriter: recorder,
		statusCode:     200,
		captureHeaders: true,
	}

	rw.WriteHeader(http.StatusAccepted)

	if rw.headers == nil {
		t.Fatal("expected response headers to be captured when enabled")
	}
	if got := rw.headers.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("expected cloned content type, got %q", got)
	}
}

func TestResponseWriter_WriteAllocatesBodyCaptureLazily(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: recorder,
		statusCode:     200,
		bodyMax:        32,
	}

	if rw.bodyCapture != nil {
		t.Fatal("expected body capture buffer to start nil")
	}

	_, err := rw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	if rw.bodyCapture == nil {
		t.Fatal("expected body capture buffer to be allocated on first write")
	}
	if string(rw.bodyCapture) != "hello" {
		t.Fatalf("expected captured body to match write, got %q", string(rw.bodyCapture))
	}
}

func TestResponseWriter_WriteHeaderOnlyOnce(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: recorder,
		statusCode:     200,
	}

	rw.WriteHeader(http.StatusNotFound)
	rw.WriteHeader(http.StatusInternalServerError) // Should be ignored

	if rw.statusCode != http.StatusNotFound {
		t.Errorf("expected status code %d, got %d (second WriteHeader should be ignored)", http.StatusNotFound, rw.statusCode)
	}
}

func TestBuildZapRequestLogFields_IncludesAIBudgetScope(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/v1/chat/completions", nil)
	rw := &responseWriter{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusOK,
	}
	requestData := &reqctx.RequestData{
		ID: "req-123",
		AIUsage: &reqctx.AIUsage{
			Provider:          "openai",
			Model:             "gpt-4o",
			BudgetScope:       "api_key",
			BudgetScopeValue:  "key-prod",
			BudgetUtilization: 0.82,
		},
	}
	cfg := DefaultRequestLoggingConfig()

	fields := buildZapRequestLogFields(
		req,
		rw,
		150*time.Millisecond,
		requestData,
		time.Now().Add(-150*time.Millisecond),
		time.Now(),
		&cfg,
		nil,
	)

	foundScope := false
	foundScopeValue := false
	for _, field := range fields {
		if field.Key == "ai_budget_scope" {
			foundScope = true
		}
		if field.Key == "ai_budget_scope_value" {
			foundScopeValue = true
		}
	}
	if !foundScope {
		t.Fatal("expected ai_budget_scope to be included in request log fields")
	}
	if !foundScopeValue {
		t.Fatal("expected ai_budget_scope_value to be included in request log fields")
	}
}

func TestRequestLoggerMiddlewareZap_FastSuccessOmitsResponseBody(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	cfg := DefaultRequestLoggingConfig()
	cfg.Sampling.Enabled = false

	handler := RequestLoggerMiddlewareZap(logger, &cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected one log entry, got %d", len(entries))
	}
	for _, field := range entries[0].Context {
		if field.Key == "response_body" {
			t.Fatal("did not expect response_body for a fast successful request")
		}
	}
}
