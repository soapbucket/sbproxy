package middleware

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestTracingResponseWriter_Hijack(t *testing.T) {
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
			w := &tracingResponseWriter{
				ResponseWriter: tt.underlying,
				statusCode:     http.StatusOK,
			}

			conn, rw, err := w.Hijack()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				if conn != nil {
					t.Error("expected nil connection")
					conn.Close()
				}
				if rw != nil {
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
				if rw == nil {
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

func TestTracingResponseWriter_ImplementsHijacker(t *testing.T) {
	w := &tracingResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusOK,
	}

	// Verify that tracingResponseWriter implements http.Hijacker
	_, ok := interface{}(w).(http.Hijacker)
	if !ok {
		t.Error("tracingResponseWriter does not implement http.Hijacker")
	}
}

func TestTracingResponseWriter_Flush(t *testing.T) {
	recorder := httptest.NewRecorder()
	w := &tracingResponseWriter{
		ResponseWriter: recorder,
		statusCode:     http.StatusOK,
	}

	// Should not panic even if underlying doesn't flush
	w.Flush()
}

func TestTracingResponseWriter_WriteHeader(t *testing.T) {
	recorder := httptest.NewRecorder()
	w := &tracingResponseWriter{
		ResponseWriter: recorder,
		statusCode:     http.StatusOK,
	}

	w.WriteHeader(http.StatusNotFound)

	if w.statusCode != http.StatusNotFound {
		t.Errorf("expected status code %d, got %d", http.StatusNotFound, w.statusCode)
	}
}

func TestTracingResponseWriter_Write(t *testing.T) {
	recorder := httptest.NewRecorder()
	w := &tracingResponseWriter{
		ResponseWriter: recorder,
		statusCode:     http.StatusOK,
	}

	data := []byte("hello world")
	n, err := w.Write(data)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}
	if w.written != int64(len(data)) {
		t.Errorf("expected written=%d, got %d", len(data), w.written)
	}
}

func TestTracingResponseWriter_Unwrap(t *testing.T) {
	recorder := httptest.NewRecorder()
	w := &tracingResponseWriter{
		ResponseWriter: recorder,
		statusCode:     http.StatusOK,
	}

	unwrapped := w.Unwrap()

	if unwrapped != recorder {
		t.Error("Unwrap() did not return the underlying ResponseWriter")
	}
}
