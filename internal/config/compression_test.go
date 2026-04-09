package config

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestCompression_GzipResponse(t *testing.T) {
	bodyContent := strings.Repeat(`{"key":"value"},`, 200)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bodyContent))
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.Compression = &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"gzip"},
		MinSize:    100,
		Level:      6,
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.RemoteAddr = "192.168.1.1:12345"

	// Use a real HTTP server to test compression end-to-end
	proxyHandler := NewStreamingProxyHandler(cfg)
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true, // Don't auto-decompress
		},
	}

	httpReq, _ := http.NewRequest("GET", proxyServer.URL+"/test", nil)
	httpReq.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Read the full response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	// Debug all headers
	t.Logf("Body length: %d (original: %d)", len(body), len(bodyContent))
	for k, v := range resp.Header {
		t.Logf("Header %s: %v", k, v)
	}

	// The body should be significantly smaller than original (compressed)
	if len(body) >= len(bodyContent) {
		t.Fatalf("body should be compressed: %d >= %d", len(body), len(bodyContent))
	}

	// Should be valid gzip
	reader, err := gzip.NewReader(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("body is not valid gzip: %v", err)
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}

	if !strings.Contains(string(decoded), `"key":"value"`) {
		t.Error("decompressed body should contain original data")
	}
}


func TestCompression_NoCompressionBelowMinSize(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("small"))
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.Compression = &CompressionConfig{
		Enable:  true,
		MinSize: 1024,
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "" {
		t.Error("should not compress small responses")
	}
}

func TestCompression_SkipsAlreadyEncoded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		w.Write([]byte(strings.Repeat("x", 2000)))
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.Compression = &CompressionConfig{
		Enable:  true,
		MinSize: 100,
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	// Should preserve original encoding, not double-compress
	if rec.Header().Get("Content-Encoding") != "br" {
		t.Errorf("expected Content-Encoding: br, got %s", rec.Header().Get("Content-Encoding"))
	}
}

func TestCompression_SkipsImageContentType(t *testing.T) {
	if !shouldCompress("image/png", &CompressionConfig{Enable: true}) {
		// Expected
	} else {
		t.Error("should not compress image/png")
	}

	if !shouldCompress("application/json", &CompressionConfig{Enable: true}) {
		t.Error("should compress application/json")
	}
}

func TestCompression_SelectEncoding(t *testing.T) {
	cfg := &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"gzip"},
	}

	result := selectEncoding("gzip", cfg)
	if result != "gzip" {
		t.Errorf("selectEncoding(gzip) = %q, want gzip", result)
	}

	result = selectEncoding("gzip, deflate", cfg)
	if result != "gzip" {
		t.Errorf("selectEncoding(gzip, deflate) = %q, want gzip", result)
	}
}

func TestCompression_WrapWithCompression(t *testing.T) {
	cfg := &Config{
		Compression: &CompressionConfig{
			Enable:     true,
			Algorithms: []string{"gzip"},
			MinSize:    100,
		},
	}

	handler := &StreamingProxyHandler{config: cfg}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept-Encoding", "gzip")

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	strategy := FlushStrategy{Type: FlushBuffered, IsStreaming: false}

	result := handler.wrapWithCompression(rec, req, resp, strategy)
	if _, ok := result.(*compressedResponseWriter); !ok {
		t.Errorf("expected *compressedResponseWriter, got %T", result)
	}
}

func TestCompression_NoAcceptEncoding(t *testing.T) {
	encoding := selectEncoding("", &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"gzip"},
	})
	if encoding != "" {
		t.Error("should return empty when no Accept-Encoding")
	}
}

func TestCompression_DirectWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"gzip"},
		MinSize:    100,
		Level:      6,
	}

	cw := &compressedResponseWriter{
		ResponseWriter: rec,
		encoding:       "gzip",
		config:         cfg,
	}

	cw.Header().Set("Content-Type", "application/json")
	cw.WriteHeader(http.StatusOK)

	body := strings.Repeat(`{"key":"value"},`, 200)
	n, err := cw.Write([]byte(body))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(body) {
		t.Errorf("expected %d bytes written, got %d", len(body), n)
	}

	cw.Close()

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("expected Content-Encoding: gzip, got %q", rec.Header().Get("Content-Encoding"))
	}

	reader, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}

	if string(decoded) != body {
		t.Error("decompressed body should match original")
	}
}

func TestCompression_QualityFactorZero(t *testing.T) {
	if containsEncoding("gzip;q=0", "gzip") {
		t.Error("should not match gzip with q=0")
	}
	if !containsEncoding("gzip;q=0.5", "gzip") {
		t.Error("should match gzip with q=0.5")
	}
}

func TestCompression_BrotliSelectEncoding(t *testing.T) {
	cfg := &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"br", "gzip"},
	}

	result := selectEncoding("br, gzip", cfg)
	if result != "br" {
		t.Errorf("selectEncoding(br, gzip) = %q, want br (preferred)", result)
	}

	result = selectEncoding("gzip", cfg)
	if result != "gzip" {
		t.Errorf("selectEncoding(gzip) = %q, want gzip (fallback)", result)
	}

	result = selectEncoding("br", cfg)
	if result != "br" {
		t.Errorf("selectEncoding(br) = %q, want br", result)
	}
}

func TestCompression_BrotliSelectEncoding_GzipPreferred(t *testing.T) {
	cfg := &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"gzip", "br"},
	}

	result := selectEncoding("br, gzip", cfg)
	if result != "gzip" {
		t.Errorf("selectEncoding with gzip first = %q, want gzip", result)
	}
}

func TestCompression_BrotliDirectWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"br"},
		MinSize:    100,
		Level:      6,
	}

	cw := &compressedResponseWriter{
		ResponseWriter: rec,
		encoding:       "br",
		config:         cfg,
	}

	cw.Header().Set("Content-Type", "application/json")
	cw.WriteHeader(http.StatusOK)

	body := strings.Repeat(`{"key":"value"},`, 200)
	n, err := cw.Write([]byte(body))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(body) {
		t.Errorf("expected %d bytes written, got %d", len(body), n)
	}

	cw.Close()

	if rec.Header().Get("Content-Encoding") != "br" {
		t.Errorf("expected Content-Encoding: br, got %q", rec.Header().Get("Content-Encoding"))
	}

	reader := brotli.NewReader(rec.Body)
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to decompress brotli: %v", err)
	}

	if string(decoded) != body {
		t.Error("decompressed body should match original")
	}
}

func TestCompression_BrotliEndToEnd(t *testing.T) {
	bodyContent := strings.Repeat(`{"data":"brotli-test"},`, 200)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bodyContent))
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.Compression = &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"br"},
		MinSize:    100,
		Level:      6,
	}

	proxyHandler := NewStreamingProxyHandler(cfg)
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	httpReq, _ := http.NewRequest("GET", proxyServer.URL+"/test", nil)
	httpReq.Header.Set("Accept-Encoding", "br")

	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	t.Logf("Body length: %d (original: %d)", len(body), len(bodyContent))

	if len(body) >= len(bodyContent) {
		t.Fatalf("body should be compressed: %d >= %d", len(body), len(bodyContent))
	}

	reader := brotli.NewReader(strings.NewReader(string(body)))
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("body is not valid brotli: %v", err)
	}

	if !strings.Contains(string(decoded), `"data":"brotli-test"`) {
		t.Error("decompressed body should contain original data")
	}
}

func TestCompression_BrotliWrapWithCompression(t *testing.T) {
	cfg := &Config{
		Compression: &CompressionConfig{
			Enable:     true,
			Algorithms: []string{"br"},
			MinSize:    100,
		},
	}

	handler := &StreamingProxyHandler{config: cfg}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept-Encoding", "br")

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	strategy := FlushStrategy{Type: FlushBuffered, IsStreaming: false}

	result := handler.wrapWithCompression(rec, req, resp, strategy)
	cw, ok := result.(*compressedResponseWriter)
	if !ok {
		t.Fatalf("expected *compressedResponseWriter, got %T", result)
	}
	if cw.encoding != "br" {
		t.Errorf("encoding = %q, want br", cw.encoding)
	}
}

func TestCompression_BrotliSmallResponseNoCompression(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"br"},
		MinSize:    1024,
	}

	cw := &compressedResponseWriter{
		ResponseWriter: rec,
		encoding:       "br",
		config:         cfg,
	}

	cw.Header().Set("Content-Type", "text/plain")

	// Write less than minSize
	cw.Write([]byte("small"))
	cw.Close()

	// Should not have Content-Encoding because body was below minSize
	if rec.Header().Get("Content-Encoding") != "" {
		t.Error("should not compress small responses with brotli")
	}
	if rec.Body.String() != "small" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "small")
	}
}

func TestCompression_BrotliFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	cfg := &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"br"},
		MinSize:    100,
	}

	cw := &compressedResponseWriter{
		ResponseWriter: rec,
		encoding:       "br",
		config:         cfg,
	}

	cw.Header().Set("Content-Type", "text/plain")
	cw.WriteHeader(http.StatusOK)

	// Write enough to trigger compression
	body := strings.Repeat("hello world ", 100)
	cw.Write([]byte(body))

	// Flush should not panic
	cw.Flush()

	cw.Close()

	if rec.Header().Get("Content-Encoding") != "br" {
		t.Errorf("Content-Encoding = %q, want br", rec.Header().Get("Content-Encoding"))
	}
}

func TestCompression_GzipStillWorks(t *testing.T) {
	// Verify gzip still works after brotli changes
	cfg := &CompressionConfig{
		Enable:     true,
		Algorithms: []string{"gzip"},
		MinSize:    100,
	}

	result := selectEncoding("gzip, br", cfg)
	if result != "gzip" {
		t.Errorf("selectEncoding = %q, want gzip (only gzip configured)", result)
	}

	rec := httptest.NewRecorder()
	cw := &compressedResponseWriter{
		ResponseWriter: rec,
		encoding:       "gzip",
		config:         cfg,
	}
	cw.Header().Set("Content-Type", "text/plain")
	cw.WriteHeader(http.StatusOK)

	body := strings.Repeat("test data ", 100)
	cw.Write([]byte(body))
	cw.Close()

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", rec.Header().Get("Content-Encoding"))
	}

	reader, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer reader.Close()
	decoded, _ := io.ReadAll(reader)
	if string(decoded) != body {
		t.Error("decompressed body should match original")
	}
}
