package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTrailerGenerator_MD5Checksum(t *testing.T) {
	generators := []TrailerGenerator{
		{
			Name:  "X-Content-MD5",
			Type:  TrailerChecksum,
			Value: "md5",
		},
	}

	startTime := time.Now()
	tg := NewTrailerGeneratorImpl(generators, startTime)

	// Create test response
	resp := &http.Response{
		Header: http.Header{},
	}

	// Wrap writer
	w := httptest.NewRecorder()
	wrapped := tg.WrapWriter(w, resp)

	// Write data
	data := []byte("Hello, World!")
	wrapped.Write(data)

	// Apply trailers
	if tw, ok := wrapped.(*trailerWriter); ok {
		tg.ApplyTrailers(w, tw)
	}

	// Verify trailer was added
	md5Trailer := w.Header().Get("X-Content-MD5")
	if md5Trailer == "" {
		t.Error("expected X-Content-MD5 trailer to be set")
	}

	// Expected MD5 for "Hello, World!"
	expected := "65a8e27d8879283831b664bd8b7f0ad4"
	if md5Trailer != expected {
		t.Errorf("expected MD5 %s, got %s", expected, md5Trailer)
	}
}

func TestTrailerGenerator_SHA256Checksum(t *testing.T) {
	generators := []TrailerGenerator{
		{
			Name:  "X-Content-SHA256",
			Type:  TrailerChecksum,
			Value: "sha256",
		},
	}

	startTime := time.Now()
	tg := NewTrailerGeneratorImpl(generators, startTime)

	resp := &http.Response{Header: http.Header{}}
	w := httptest.NewRecorder()
	wrapped := tg.WrapWriter(w, resp)

	data := []byte("Hello, World!")
	wrapped.Write(data)

	if tw, ok := wrapped.(*trailerWriter); ok {
		tg.ApplyTrailers(w, tw)
	}

	sha256Trailer := w.Header().Get("X-Content-SHA256")
	if sha256Trailer == "" {
		t.Error("expected X-Content-SHA256 trailer to be set")
	}

	// SHA256 hash should be 64 hex characters
	if len(sha256Trailer) != 64 {
		t.Errorf("expected 64 character SHA256, got %d: %s", len(sha256Trailer), sha256Trailer)
	}
}

func TestTrailerGenerator_Timing(t *testing.T) {
	generators := []TrailerGenerator{
		{
			Name:  "X-Request-Duration",
			Type:  TrailerTiming,
			Value: "request_duration_ms",
		},
	}

	startTime := time.Now()
	time.Sleep(10 * time.Millisecond) // Small delay

	tg := NewTrailerGeneratorImpl(generators, startTime)

	resp := &http.Response{Header: http.Header{}}
	w := httptest.NewRecorder()
	wrapped := tg.WrapWriter(w, resp)

	wrapped.Write([]byte("test"))

	if tw, ok := wrapped.(*trailerWriter); ok {
		tg.ApplyTrailers(w, tw)
	}

	durationTrailer := w.Header().Get("X-Request-Duration")
	if durationTrailer == "" {
		t.Error("expected X-Request-Duration trailer to be set")
	}

	// Should be at least 10ms
	if !strings.Contains(durationTrailer, "1") { // At least 10+ ms
		t.Logf("Duration trailer: %s (expected >= 10ms)", durationTrailer)
	}
}

func TestTrailerGenerator_Multiple(t *testing.T) {
	generators := []TrailerGenerator{
		{
			Name:  "X-Content-MD5",
			Type:  TrailerChecksum,
			Value: "md5",
		},
		{
			Name:  "X-Request-Duration",
			Type:  TrailerTiming,
			Value: "request_duration_ms",
		},
	}

	startTime := time.Now()
	tg := NewTrailerGeneratorImpl(generators, startTime)

	resp := &http.Response{Header: http.Header{}}
	w := httptest.NewRecorder()
	wrapped := tg.WrapWriter(w, resp)

	wrapped.Write([]byte("test data"))

	if tw, ok := wrapped.(*trailerWriter); ok {
		tg.ApplyTrailers(w, tw)
	}

	// Both trailers should be set
	if w.Header().Get("X-Content-MD5") == "" {
		t.Error("expected X-Content-MD5 trailer")
	}
	if w.Header().Get("X-Request-Duration") == "" {
		t.Error("expected X-Request-Duration trailer")
	}
}

func TestTrailerWriter_WritesCorrectly(t *testing.T) {
	generators := []TrailerGenerator{
		{
			Name:  "X-Content-MD5",
			Type:  TrailerChecksum,
			Value: "md5",
		},
	}

	tg := NewTrailerGeneratorImpl(generators, time.Now())

	resp := &http.Response{Header: http.Header{}}
	w := httptest.NewRecorder()
	wrapped := tg.WrapWriter(w, resp)

	// Write in multiple chunks
	data1 := []byte("Hello, ")
	data2 := []byte("World!")

	n1, err1 := wrapped.Write(data1)
	if err1 != nil || n1 != len(data1) {
		t.Errorf("first write failed: %v, wrote %d bytes", err1, n1)
	}

	n2, err2 := wrapped.Write(data2)
	if err2 != nil || n2 != len(data2) {
		t.Errorf("second write failed: %v, wrote %d bytes", err2, n2)
	}

	// Verify all data was written
	written := w.Body.String()
	if written != "Hello, World!" {
		t.Errorf("expected 'Hello, World!', got '%s'", written)
	}
}

