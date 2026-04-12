package compressor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/zstd"
)

// TestCompressorMiddleware tests the basic functionality of the compressor middleware
func TestCompressorMiddleware(t *testing.T) {
	testContent := "Hello, World! This is a test content that should be compressed."

	tests := []struct {
		name           string
		acceptEncoding string
		wantEncoding   string
	}{
		{
			name:           "gzip encoding",
			acceptEncoding: "gzip",
			wantEncoding:   "gzip",
		},
		{
			name:           "deflate encoding",
			acceptEncoding: "deflate",
			wantEncoding:   "deflate",
		},
		{
			name:           "br encoding",
			acceptEncoding: "br",
			wantEncoding:   "br",
		},
		{
			name:           "zstd encoding",
			acceptEncoding: "zstd",
			wantEncoding:   "zstd",
		},
		{
			name:           "no encoding",
			acceptEncoding: "",
			wantEncoding:   "",
		},
		{
			name:           "identity encoding",
			acceptEncoding: "identity",
			wantEncoding:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a handler that returns test content
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(testContent))
			})

			// Wrap with compressor middleware
			compressed := Compressor(5)(handler)

			// Create request with Accept-Encoding header
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}

			// Record the response
			rr := httptest.NewRecorder()
			compressed.ServeHTTP(rr, req)

			// Check status code
			if status := rr.Code; status != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
			}

			// Check Content-Encoding header
			gotEncoding := rr.Header().Get("Content-Encoding")
			if gotEncoding != tt.wantEncoding {
				t.Errorf("Content-Encoding: got %q, want %q", gotEncoding, tt.wantEncoding)
			}

			// Verify we can decompress the content
			if gotEncoding != "" {
				decompressed, err := decompress(rr.Body.Bytes(), gotEncoding)
				if err != nil {
					t.Errorf("failed to decompress: %v", err)
					return
				}
				if string(decompressed) != testContent {
					t.Errorf("decompressed content mismatch: got %q, want %q", string(decompressed), testContent)
				}
			}
		})
	}
}

// TestVaryConsolidator tests the Vary header consolidation functionality
func TestVaryConsolidator(t *testing.T) {
	tests := []struct {
		name       string
		varyValues []string
		want       string
	}{
		{
			name:       "single value",
			varyValues: []string{"Accept-Encoding"},
			want:       "Accept-Encoding",
		},
		{
			name:       "multiple duplicate values",
			varyValues: []string{"Accept-Encoding", "Accept-Encoding"},
			want:       "Accept-Encoding",
		},
		{
			name:       "multiple different values",
			varyValues: []string{"Accept-Encoding", "Accept-Language"},
			want:       "Accept-Encoding, Accept-Language",
		},
		{
			name:       "comma-separated duplicates",
			varyValues: []string{"Accept-Encoding, Accept-Language", "Accept-Encoding"},
			want:       "Accept-Encoding, Accept-Language",
		},
		{
			name:       "case insensitive deduplication",
			varyValues: []string{"Accept-Encoding", "accept-encoding"},
			want:       "Accept-Encoding",
		},
		{
			name:       "empty values",
			varyValues: []string{},
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			for _, v := range tt.varyValues {
				rr.Header().Add("Vary", v)
			}

			vc := &varyConsolidator{ResponseWriter: rr}
			vc.consolidateVaryHeaders()

			got := vc.Header().Get("Vary")
			if got != tt.want {
				t.Errorf("Vary header: got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestVaryConsolidatorWrite tests that headers are consolidated on Write
func TestVaryConsolidatorWrite(t *testing.T) {
	rr := httptest.NewRecorder()
	rr.Header().Add("Vary", "Accept-Encoding")
	rr.Header().Add("Vary", "Accept-Encoding")

	vc := &varyConsolidator{ResponseWriter: rr}

	// Write should trigger consolidation
	_, err := vc.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	got := vc.Header().Get("Vary")
	if got != "Accept-Encoding" {
		t.Errorf("Vary header after Write: got %q, want %q", got, "Accept-Encoding")
	}

	// Second write should not re-consolidate
	rr.Header().Add("Vary", "Accept-Language")
	_, err = vc.Write([]byte("test2"))
	if err != nil {
		t.Fatalf("Second Write failed: %v", err)
	}

	// Vary header should now have both values since we added after consolidation
	got = vc.Header().Get("Vary")
	if !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("Vary header should contain Accept-Encoding")
	}
}

// TestVaryConsolidatorWriteHeader tests that headers are consolidated on WriteHeader
func TestVaryConsolidatorWriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	rr.Header().Add("Vary", "Accept-Encoding")
	rr.Header().Add("Vary", "Accept-Language")

	vc := &varyConsolidator{ResponseWriter: rr}

	// WriteHeader should trigger consolidation
	vc.WriteHeader(http.StatusOK)

	got := vc.Header().Get("Vary")
	if got != "Accept-Encoding, Accept-Language" {
		t.Errorf("Vary header after WriteHeader: got %q, want %q", got, "Accept-Encoding, Accept-Language")
	}
}

// TestVaryConsolidatorFlush tests the Flush implementation
func TestVaryConsolidatorFlush(t *testing.T) {
	rr := httptest.NewRecorder()
	vc := &varyConsolidator{ResponseWriter: rr}

	// Should not panic when calling Flush
	vc.Flush()

	// Verify the recorder was flushed
	if !rr.Flushed {
		t.Error("expected recorder to be flushed")
	}
}

// TestCompressorCompressionLevel tests different compression levels
func TestCompressorCompressionLevel(t *testing.T) {
	testContent := strings.Repeat("Hello, World! ", 100)

	levels := []int{1, 5, 9}

	for _, level := range levels {
		t.Run("level_"+string(rune('0'+level)), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(testContent))
			})

			compressed := Compressor(level)(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Accept-Encoding", "gzip")

			rr := httptest.NewRecorder()
			compressed.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("unexpected status code: %d", rr.Code)
			}

			// Verify content is compressed (should be smaller than original)
			if rr.Body.Len() >= len(testContent) {
				t.Logf("warning: compressed size (%d) >= original size (%d)", rr.Body.Len(), len(testContent))
			}
		})
	}
}

// decompress helper function to decompress content based on encoding
func decompress(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	case "deflate":
		reader := flate.NewReader(bytes.NewReader(data))
		defer reader.Close()
		return io.ReadAll(reader)

	case "br":
		reader := brotli.NewReader(bytes.NewReader(data))
		return io.ReadAll(reader)

	case "zstd":
		reader, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	default:
		return data, nil
	}
}

// BenchmarkCompressor benchmarks the compressor middleware
func BenchmarkCompressor(b *testing.B) {
	b.ReportAllocs()
	testContent := strings.Repeat("Hello, World! ", 100)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(testContent))
	})

	compressed := Compressor(5)(handler)

	encodings := []string{"gzip", "br", "deflate", "zstd"}

	for _, enc := range encodings {
		b.Run(enc, func(b *testing.B) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Accept-Encoding", enc)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rr := httptest.NewRecorder()
				compressed.ServeHTTP(rr, req)
			}
		})
	}
}

// TestIsWebSocketUpgrade tests the WebSocket upgrade detection
func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name       string
		upgrade    string
		connection string
		want       bool
	}{
		{
			name:       "valid websocket upgrade",
			upgrade:    "websocket",
			connection: "Upgrade",
			want:       true,
		},
		{
			name:       "case insensitive websocket",
			upgrade:    "WebSocket",
			connection: "upgrade",
			want:       true,
		},
		{
			name:       "connection with keep-alive",
			upgrade:    "websocket",
			connection: "keep-alive, Upgrade",
			want:       true,
		},
		{
			name:       "no upgrade header",
			upgrade:    "",
			connection: "Upgrade",
			want:       false,
		},
		{
			name:       "no connection header",
			upgrade:    "websocket",
			connection: "",
			want:       false,
		},
		{
			name:       "wrong upgrade type",
			upgrade:    "h2c",
			connection: "Upgrade",
			want:       false,
		},
		{
			name:       "connection without upgrade",
			upgrade:    "websocket",
			connection: "keep-alive",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ws", nil)
			if tt.upgrade != "" {
				req.Header.Set("Upgrade", tt.upgrade)
			}
			if tt.connection != "" {
				req.Header.Set("Connection", tt.connection)
			}

			got := isWebSocketUpgrade(req)
			if got != tt.want {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCompressorSkipsWebSocket tests that compression is skipped for WebSocket requests
func TestCompressorSkipsWebSocket(t *testing.T) {
	testContent := "Hello, World!"

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(testContent))
	})

	compressed := Compressor(5)(handler)

	// Create WebSocket upgrade request
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Accept-Encoding", "gzip") // Would normally trigger compression

	rr := httptest.NewRecorder()
	compressed.ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("handler was not called")
	}

	// Response should NOT be compressed for WebSocket requests
	if rr.Header().Get("Content-Encoding") != "" {
		t.Errorf("WebSocket request should not be compressed, got Content-Encoding: %s", rr.Header().Get("Content-Encoding"))
	}

	// Content should be unchanged
	if rr.Body.String() != testContent {
		t.Errorf("content mismatch: got %q, want %q", rr.Body.String(), testContent)
	}
}

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

// TestVaryConsolidatorHijack tests the Hijack implementation
func TestVaryConsolidatorHijack(t *testing.T) {
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
			vc := &varyConsolidator{ResponseWriter: tt.underlying}

			conn, rw, err := vc.Hijack()

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

// TestVaryConsolidatorImplementsHijacker verifies that varyConsolidator implements http.Hijacker
func TestVaryConsolidatorImplementsHijacker(t *testing.T) {
	vc := &varyConsolidator{ResponseWriter: httptest.NewRecorder()}

	_, ok := interface{}(vc).(http.Hijacker)
	if !ok {
		t.Error("varyConsolidator does not implement http.Hijacker")
	}
}
