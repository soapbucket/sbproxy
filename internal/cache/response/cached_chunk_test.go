package responsecache

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestCachedChunkedResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	crw := &CachedChunkedResponseWriter{
		headers:  make(http.Header),
		rw:       w,
		offset:   0,
		status:   0,
		flusher:  w,
		protocol: "HTTP/1.1",
	}

	// Test Header()
	header := crw.Header()
	if header == nil {
		t.Error("Expected header to be non-nil")
	}

	// Test WriteHeader()
	crw.WriteHeader(http.StatusOK)
	if crw.status != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, crw.status)
	}

	// Test Write() with no offset
	data := []byte("test data")
	n, err := crw.Write(data)
	if err != nil {
		t.Errorf("Write() error = %v", err)
	}
	if n != len(data) {
		t.Errorf("Write() returned %d, expected %d", n, len(data))
	}

	// Test Write() with offset
	crw.offset = 5
	moreData := []byte("more data")
	n, err = crw.Write(moreData)
	if err != nil {
		t.Errorf("Write() with offset error = %v", err)
	}
	if n != len(moreData) {
		t.Errorf("Write() with offset returned %d, expected %d", n, len(moreData))
	}

	// Test Flush()
	crw.Flush() // Should not panic
}

func TestCachedChunkedResponseWriter_WriteHeader(t *testing.T) {
	w := httptest.NewRecorder()
	crw := &CachedChunkedResponseWriter{
		headers:        make(http.Header),
		writtenHeaders: make(http.Header),
		rw:             w,
		offset:         0,
		status:         0,
		flusher:        w,
		protocol:       "HTTP/1.1",
	}

	// Set some headers
	crw.headers.Set("Content-Type", "text/plain")
	crw.headers.Set("Content-Length", "100")

	// Call WriteHeader
	crw.WriteHeader(http.StatusOK)

	// Check that Content-Length was removed
	if crw.headers.Get("Content-Length") != "" {
		t.Error("Expected Content-Length to be removed")
	}

	// Check that headers were converted to trailers (for HTTP/1.1)
	if crw.headers.Get("Content-Type") != "" {
		t.Error("Expected Content-Type to be moved to trailers")
	}
	if crw.headers.Get(http.TrailerPrefix+"Content-Type") == "" {
		t.Error("Expected Content-Type to be in trailers")
	}
}

func TestCachedChunkedResponseWriter_WriteHeader_HTTP3(t *testing.T) {
	w := httptest.NewRecorder()
	crw := &CachedChunkedResponseWriter{
		headers:        make(http.Header),
		writtenHeaders: make(http.Header),
		rw:             w,
		offset:         0,
		status:         0,
		flusher:        w,
		protocol:       "HTTP/3.0", // HTTP/3 protocol
	}

	// Set some headers
	crw.headers.Set("Content-Type", "text/plain")
	crw.headers.Set("Content-Length", "100")

	// Call WriteHeader
	crw.WriteHeader(http.StatusOK)

	// Check that Content-Length was removed
	if crw.headers.Get("Content-Length") != "" {
		t.Error("Expected Content-Length to be removed")
	}

	// For HTTP/3, headers should NOT be converted to trailers
	// HTTP/3 uses QUIC streams which handle framing natively
	if crw.headers.Get("Content-Type") == "" {
		t.Error("Expected Content-Type to remain as regular header for HTTP/3")
	}
	if crw.headers.Get(http.TrailerPrefix+"Content-Type") != "" {
		t.Error("Expected no trailer conversion for HTTP/3")
	}
}

func TestGetCachedChunkResponse(t *testing.T) {
	store := NewMockKVStore()
	URL, _ := url.Parse("http://example.com/test")

	// Test with no cached response
	_, found := GetCachedChunkResponse(store, URL)
	if found {
		t.Error("Expected no cached chunk response to be found")
	}

	// Test with cached response
	cachedChunk := &CachedChunkedResponse{
		Headers: http.Header{"Content-Type": []string{"text/plain"}},
		Body:    []byte("chunk data"),
	}

	// Save the chunk first
	err := SaveCachedChunkResponse(store, URL, cachedChunk, time.Hour)
	if err != nil {
		t.Fatalf("SaveCachedChunkResponse() error = %v", err)
	}

	// Now try to get it
	chunk, found := GetCachedChunkResponse(store, URL)
	if !found {
		t.Error("Expected cached chunk response to be found")
	}
	if chunk.Headers.Get("Content-Type") != "text/plain" {
		t.Errorf("Expected Content-Type 'text/plain', got '%s'", chunk.Headers.Get("Content-Type"))
	}
	if string(chunk.Body) != "chunk data" {
		t.Errorf("Expected body 'chunk data', got '%s'", string(chunk.Body))
	}
}

func TestSaveCachedChunkResponse(t *testing.T) {
	store := NewMockKVStore()
	URL, _ := url.Parse("http://example.com/test")

	cachedChunk := &CachedChunkedResponse{
		Headers: http.Header{"Content-Type": []string{"text/plain"}},
		Body:    []byte("chunk data"),
	}

	err := SaveCachedChunkResponse(store, URL, cachedChunk, time.Hour)
	if err != nil {
		t.Errorf("SaveCachedChunkResponse() error = %v", err)
	}

	// Verify it was saved
	_, found := GetCachedChunkResponse(store, URL)
	if !found {
		t.Error("Expected cached chunk response to be found after saving")
	}
}
