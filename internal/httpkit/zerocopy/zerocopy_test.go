package zerocopy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBufferPool(t *testing.T) {
	// Test buffer pool
	buf1 := GetBuffer()
	if len(buf1) != DefaultBufferSize {
		t.Errorf("Expected buffer size %d, got %d", DefaultBufferSize, len(buf1))
	}
	PutBuffer(buf1)

	// Get another buffer - should reuse
	buf2 := GetBuffer()
	if len(buf2) != DefaultBufferSize {
		t.Errorf("Expected buffer size %d, got %d", DefaultBufferSize, len(buf2))
	}
	PutBuffer(buf2)

	// Test large buffer pool
	largeBuf := GetLargeBuffer()
	if len(largeBuf) != LargeBufferSize {
		t.Errorf("Expected large buffer size %d, got %d", LargeBufferSize, len(largeBuf))
	}
	PutLargeBuffer(largeBuf)

	// Test small buffer pool
	smallBuf := GetSmallBuffer()
	if len(smallBuf) != SmallBufferSize {
		t.Errorf("Expected small buffer size %d, got %d", SmallBufferSize, len(smallBuf))
	}
	PutSmallBuffer(smallBuf)
}

func TestCopyBuffer(t *testing.T) {
	src := strings.NewReader("test data for zero-copy")
	dst := &bytes.Buffer{}

	written, err := CopyBuffer(dst, src)
	if err != nil {
		t.Fatalf("CopyBuffer failed: %v", err)
	}

	if written != int64(len("test data for zero-copy")) {
		t.Errorf("Expected %d bytes written, got %d", len("test data for zero-copy"), written)
	}

	if dst.String() != "test data for zero-copy" {
		t.Errorf("Expected %q, got %q", "test data for zero-copy", dst.String())
	}
}

func TestCopyBufferLarge(t *testing.T) {
	// Create large data
	largeData := strings.Repeat("x", 300*1024) // 300KB
	src := strings.NewReader(largeData)
	dst := &bytes.Buffer{}

	written, err := CopyBufferLarge(dst, src)
	if err != nil {
		t.Fatalf("CopyBufferLarge failed: %v", err)
	}

	if written != int64(len(largeData)) {
		t.Errorf("Expected %d bytes written, got %d", len(largeData), written)
	}

	if dst.String() != largeData {
		t.Error("Data mismatch")
	}
}

func TestReadAllPooled(t *testing.T) {
	data := "test data for pooled read"
	src := strings.NewReader(data)

	result, err := ReadAllPooled(src)
	if err != nil {
		t.Fatalf("ReadAllPooled failed: %v", err)
	}

	if string(result) != data {
		t.Errorf("Expected %q, got %q", data, string(result))
	}
}

func TestReadAllPooledWithLimit(t *testing.T) {
	data := strings.Repeat("x", 1000)
	src := strings.NewReader(data)

	// Test within limit
	result, err := ReadAllPooledWithLimit(src, 2000)
	if err != nil {
		t.Fatalf("ReadAllPooledWithLimit failed: %v", err)
	}

	if len(result) != len(data) {
		t.Errorf("Expected %d bytes, got %d", len(data), len(result))
	}

	// Test exceeding limit
	src2 := strings.NewReader(data)
	_, err = ReadAllPooledWithLimit(src2, 500)
	if err == nil {
		t.Error("Expected error when limit exceeded")
	}
}

func TestStreamingWriter(t *testing.T) {
	dst := &bytes.Buffer{}
	sw := NewStreamingWriter(dst)
	defer sw.Close()

	data := "test data"
	n, err := sw.Write([]byte(data))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(data) {
		t.Errorf("Expected %d bytes written, got %d", len(data), n)
	}

	if dst.String() != data {
		t.Errorf("Expected %q, got %q", data, dst.String())
	}
}

func TestStreamingWriterLarge(t *testing.T) {
	dst := &bytes.Buffer{}
	sw := NewStreamingWriter(dst)
	defer sw.Close()

	// Write data larger than buffer
	largeData := strings.Repeat("x", 200*1024)
	n, err := sw.Write([]byte(largeData))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(largeData) {
		t.Errorf("Expected %d bytes written, got %d", len(largeData), n)
	}

	if dst.String() != largeData {
		t.Error("Large data mismatch")
	}
}

func TestTeeReader(t *testing.T) {
	src := strings.NewReader("test data")
	dst := &bytes.Buffer{}

	tr := NewTeeReader(src, dst)

	result := make([]byte, 100)
	n, err := tr.Read(result)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}

	if n != len("test data") {
		t.Errorf("Expected %d bytes read, got %d", len("test data"), n)
	}

	if dst.String() != "test data" {
		t.Errorf("Expected tee writer to receive %q, got %q", "test data", dst.String())
	}
}

func TestMultiWriter(t *testing.T) {
	dst1 := &bytes.Buffer{}
	dst2 := &bytes.Buffer{}

	mw := NewMultiWriter(dst1, dst2)
	defer mw.Close()

	data := "test data"
	n, err := mw.Write([]byte(data))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(data) {
		t.Errorf("Expected %d bytes written, got %d", len(data), n)
	}

	if dst1.String() != data {
		t.Errorf("Expected dst1 to receive %q, got %q", data, dst1.String())
	}

	if dst2.String() != data {
		t.Errorf("Expected dst2 to receive %q, got %q", data, dst2.String())
	}
}

func TestLimitedReader(t *testing.T) {
	data := strings.Repeat("x", 1000)
	src := strings.NewReader(data)

	lr := NewLimitedReader(src, 100)

	result := make([]byte, 200)
	n, err := lr.Read(result)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}

	if n != 100 {
		t.Errorf("Expected 100 bytes read, got %d", n)
	}

	if lr.N != 0 {
		t.Errorf("Expected remaining limit 0, got %d", lr.N)
	}
}

func TestForwardResponse(t *testing.T) {
	// Create a mock response
	body := strings.NewReader("response body")
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
			"X-Custom":     []string{"value"},
		},
		Body: io.NopCloser(body),
	}

	dst := &bytes.Buffer{}
	dstHeader := make(http.Header)

	// Create a mock ResponseWriter
	rw := &mockResponseWriter{
		header: dstHeader,
		body:   dst,
		status: 0,
	}

	err := ForwardResponse(rw, resp)
	if err != nil {
		t.Fatalf("ForwardResponse failed: %v", err)
	}

	if rw.status != 200 {
		t.Errorf("Expected status 200, got %d", rw.status)
	}

	if dstHeader.Get("Content-Type") != "text/plain" {
		t.Errorf("Expected Content-Type text/plain, got %s", dstHeader.Get("Content-Type"))
	}

	if dst.String() != "response body" {
		t.Errorf("Expected body %q, got %q", "response body", dst.String())
	}
}

func TestShouldUseZeroCopy(t *testing.T) {
	tests := []struct {
		name      string
		resp      *http.Response
		threshold int64
		expected  bool
	}{
		{
			name: "large response",
			resp: &http.Response{
				ContentLength: 200 * 1024, // 200KB
			},
			threshold: 100 * 1024, // 100KB threshold
			expected:  true,
		},
		{
			name: "small response",
			resp: &http.Response{
				ContentLength: 50 * 1024, // 50KB
			},
			threshold: 100 * 1024, // 100KB threshold
			expected:  false,
		},
		{
			name: "chunked response",
			resp: &http.Response{
				TransferEncoding: []string{"chunked"},
			},
			threshold: 100 * 1024,
			expected:  true,
		},
		{
			name: "unknown length",
			resp: &http.Response{
				ContentLength: -1,
			},
			threshold: 100 * 1024,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldUseZeroCopy(tt.resp, tt.threshold)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCopyWithZeroCopy(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		size     int64
		expected int
	}{
		{
			name:     "small data",
			data:     strings.Repeat("x", 1000),
			size:     1000,
			expected: 1000,
		},
		{
			name:     "large data",
			data:     strings.Repeat("x", 300*1024),
			size:     300 * 1024,
			expected: 300 * 1024,
		},
		{
			name:     "unknown size",
			data:     strings.Repeat("x", 5000),
			size:     -1,
			expected: 5000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := strings.NewReader(tt.data)
			dst := &bytes.Buffer{}

			written, err := CopyWithZeroCopy(dst, src, tt.size)
			if err != nil {
				t.Fatalf("CopyWithZeroCopy failed: %v", err)
			}

			if written != int64(tt.expected) {
				t.Errorf("Expected %d bytes written, got %d", tt.expected, written)
			}

			if dst.String() != tt.data {
				t.Error("Data mismatch")
			}
		})
	}
}

func TestReadBodyZeroCopy(t *testing.T) {
	body := strings.NewReader("test body data")
	readCloser := io.NopCloser(body)

	result, err := ReadBodyZeroCopy(readCloser, 0)
	if err != nil {
		t.Fatalf("ReadBodyZeroCopy failed: %v", err)
	}

	if string(result) != "test body data" {
		t.Errorf("Expected %q, got %q", "test body data", string(result))
	}
}

func TestReadBodyZeroCopyWithLimit(t *testing.T) {
	body := strings.NewReader("test body data")
	readCloser := io.NopCloser(body)

	result, err := ReadBodyZeroCopy(readCloser, 100)
	if err != nil {
		t.Fatalf("ReadBodyZeroCopy failed: %v", err)
	}

	if string(result) != "test body data" {
		t.Errorf("Expected %q, got %q", "test body data", string(result))
	}

	// Test with limit exceeded
	body2 := strings.NewReader(strings.Repeat("x", 200))
	readCloser2 := io.NopCloser(body2)

	_, err = ReadBodyZeroCopy(readCloser2, 100)
	if err == nil {
		t.Error("Expected error when limit exceeded")
	}
}

// mockResponseWriter implements http.ResponseWriter for testing
type mockResponseWriter struct {
	header http.Header
	body   *bytes.Buffer
	status int
}

func (m *mockResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	return m.body.Write(b)
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.status = statusCode
}

