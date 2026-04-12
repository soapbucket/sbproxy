package zerocopy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestZeroCopyTransport(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("test response body"))
	}))
	defer server.Close()

	// Create transport with zero-copy
	client := &http.Client{
		Transport: NewZeroCopyTransport(http.DefaultTransport),
	}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response using zero-copy
	body, err := ReadBodyZeroCopy(resp.Body, 0)
	if err != nil {
		t.Fatalf("ReadBodyZeroCopy failed: %v", err)
	}

	if string(body) != "test response body" {
		t.Errorf("Expected %q, got %q", "test response body", string(body))
	}
}

func TestForwardResponseIntegration(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom", "value")
		w.WriteHeader(201)
		w.Write([]byte(`{"status": "created"}`))
	}))
	defer server.Close()

	// Make request
	client := http.DefaultClient
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Forward response using zero-copy
	dst := httptest.NewRecorder()
	err = ForwardResponse(dst, resp)
	if err != nil {
		t.Fatalf("ForwardResponse failed: %v", err)
	}

	if dst.Code != 201 {
		t.Errorf("Expected status 201, got %d", dst.Code)
	}

	if dst.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", dst.Header().Get("Content-Type"))
	}

	if dst.Body.String() != `{"status": "created"}` {
		t.Errorf("Expected body %q, got %q", `{"status": "created"}`, dst.Body.String())
	}
}

func TestForwardResponseStreamingIntegration(t *testing.T) {
	// Create large response
	largeData := strings.Repeat("x", 500*1024) // 500KB

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		w.Write([]byte(largeData))
	}))
	defer server.Close()

	client := http.DefaultClient
	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	dst := httptest.NewRecorder()
	err = ForwardResponseStreaming(dst, resp)
	if err != nil {
		t.Fatalf("ForwardResponseStreaming failed: %v", err)
	}

	if dst.Body.Len() != len(largeData) {
		t.Errorf("Expected %d bytes, got %d", len(largeData), dst.Body.Len())
	}
}

func TestOptimizeRequest(t *testing.T) {
	body := strings.NewReader("test body")
	req := &http.Request{
		Body: io.NopCloser(body),
	}

	restore := OptimizeRequest(req)
	defer restore()

	// GetBody should NOT be set by OptimizeRequest for single-use streams.
	// Callers that need retry support should use MakeRequestRetryable instead.
	if req.GetBody != nil {
		t.Error("GetBody should not be set for single-use body streams")
	}

	// The body should still be readable after optimization
	data, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	if string(data) != "test body" {
		t.Errorf("Expected body %q, got %q", "test body", string(data))
	}

	// Restore should not panic
	restore()
}

func TestOptimizeResponse(t *testing.T) {
	resp := &http.Response{
		StatusCode:    200,
		ContentLength: 1000,
		Header:        make(http.Header),
	}

	OptimizeResponse(resp)

	// Should not modify response, just optimize metadata
	if resp.StatusCode != 200 {
		t.Error("Status code should not be modified")
	}
}

func TestTeeReaderIntegration(t *testing.T) {
	src := strings.NewReader("source data")
	dst1 := &bytes.Buffer{}
	dst2 := &bytes.Buffer{}

	// Create tee reader
	tr := NewTeeReader(src, dst1)

	// Read through tee reader
	result := make([]byte, 100)
	n, err := tr.Read(result)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}

	// Verify tee writer received data
	if dst1.String() != "source data" {
		t.Errorf("Expected tee writer to receive %q, got %q", "source data", dst1.String())
	}

	// Verify reader received data
	if string(result[:n]) != "source data" {
		t.Errorf("Expected reader to receive %q, got %q", "source data", string(result[:n]))
	}

	// Verify both destinations are independent
	if dst1.String() == dst2.String() && dst2.Len() > 0 {
		t.Error("Destinations should be independent")
	}
}

func TestMultiWriterIntegration(t *testing.T) {
	dst1 := &bytes.Buffer{}
	dst2 := &bytes.Buffer{}
	dst3 := &bytes.Buffer{}

	mw := NewMultiWriter(dst1, dst2, dst3)
	defer mw.Close()

	data := "test data for multi-writer"
	n, err := mw.Write([]byte(data))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(data) {
		t.Errorf("Expected %d bytes written, got %d", len(data), n)
	}

	// Verify all writers received data
	if dst1.String() != data {
		t.Errorf("dst1: Expected %q, got %q", data, dst1.String())
	}
	if dst2.String() != data {
		t.Errorf("dst2: Expected %q, got %q", data, dst2.String())
	}
	if dst3.String() != data {
		t.Errorf("dst3: Expected %q, got %q", data, dst3.String())
	}
}

func TestBufferReuse(t *testing.T) {
	// Test that buffers are actually reused
	buf1 := GetBuffer()
	ptr1 := &buf1[0] // Get pointer to first element

	PutBuffer(buf1)

	buf2 := GetBuffer()
	ptr2 := &buf2[0]

	// Buffers might be reused (same pointer) or new (different pointer)
	// Both are valid - we just want to ensure Put/Get works
	if len(buf2) != DefaultBufferSize {
		t.Errorf("Expected buffer size %d, got %d", DefaultBufferSize, len(buf2))
	}

	PutBuffer(buf2)

	// Test that we can get multiple buffers
	buf3 := GetBuffer()
	buf4 := GetBuffer()

	if len(buf3) != DefaultBufferSize || len(buf4) != DefaultBufferSize {
		t.Error("Buffers should have correct size")
	}

	PutBuffer(buf3)
	PutBuffer(buf4)

	// Suppress unused variable warning
	_ = ptr1
	_ = ptr2
}

func TestReadAllPooledLarge(t *testing.T) {
	// Test with data larger than default buffer
	largeData := strings.Repeat("x", 200*1024) // 200KB
	src := strings.NewReader(largeData)

	result, err := ReadAllPooled(src)
	if err != nil {
		t.Fatalf("ReadAllPooled failed: %v", err)
	}

	if len(result) != len(largeData) {
		t.Errorf("Expected %d bytes, got %d", len(largeData), len(result))
	}

	if string(result) != largeData {
		t.Error("Large data mismatch")
	}
}

func TestCopyBufferPerformance(t *testing.T) {
	// Test that CopyBuffer works correctly with various sizes
	sizes := []int{100, 1000, 10000, 100000, 1000000}

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			data := strings.Repeat("x", size)
			src := strings.NewReader(data)
			dst := &bytes.Buffer{}

			written, err := CopyBuffer(dst, src)
			if err != nil {
				t.Fatalf("CopyBuffer failed: %v", err)
			}

			if written != int64(size) {
				t.Errorf("Expected %d bytes written, got %d", size, written)
			}

			if dst.String() != data {
				t.Error("Data mismatch")
			}
		})
	}
}

