package httputil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Test basic streaming functions without manager dependencies
func TestBasicStreaming(t *testing.T) {
	t.Run("writeChunkedBody", func(t *testing.T) {
		testData := "hello world"
		var buf bytes.Buffer

		err := writeChunkedBody(&buf, strings.NewReader(testData))
		if err != nil {
			t.Errorf("writeChunkedBody() error = %v", err)
			return
		}

		// Verify chunked format
		reader := bytes.NewReader(buf.Bytes())
		var chunkSize uint32
		if err := binary.Read(reader, binary.BigEndian, &chunkSize); err != nil {
			t.Errorf("Failed to read chunk size: %v", err)
			return
		}

		if chunkSize != uint32(len(testData)) {
			t.Errorf("Chunk size = %v, want %v", chunkSize, len(testData))
		}

		// Read chunk data
		chunkData := make([]byte, chunkSize)
		if _, err := io.ReadFull(reader, chunkData); err != nil {
			t.Errorf("Failed to read chunk data: %v", err)
			return
		}

		if string(chunkData) != testData {
			t.Errorf("Chunk data = %v, want %v", string(chunkData), testData)
		}

		// Check end marker
		var endMarker uint32
		if err := binary.Read(reader, binary.BigEndian, &endMarker); err != nil {
			t.Errorf("Failed to read end marker: %v", err)
			return
		}

		if endMarker != 0 {
			t.Errorf("End marker = %v, want 0", endMarker)
		}
	})

	t.Run("chunkedReader", func(t *testing.T) {
		testData := "hello world"
		var buf bytes.Buffer

		// Write chunked data
		if err := writeChunkedBody(&buf, strings.NewReader(testData)); err != nil {
			t.Fatalf("writeChunkedBody() error = %v", err)
		}

		// Read it back
		reader := &chunkedReader{reader: &buf}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
			return
		}

		if string(body) != testData {
			t.Errorf("Body = %v, want %v", string(body), testData)
		}
	})

	t.Run("shouldCompress", func(t *testing.T) {
		tests := []struct {
			name     string
			response *http.Response
			want     bool
		}{
			{
				name: "small text response",
				response: &http.Response{
					Header:        http.Header{"Content-Type": []string{"text/plain"}},
					ContentLength: 100,
				},
				want: false,
			},
			{
				name: "large text response",
				response: &http.Response{
					Header:        http.Header{"Content-Type": []string{"text/plain"}},
					ContentLength: 2000,
				},
				want: true,
			},
			{
				name: "image response",
				response: &http.Response{
					Header:        http.Header{"Content-Type": []string{"image/jpeg"}},
					ContentLength: 5000,
				},
				want: false,
			},
			{
				name: "already compressed",
				response: &http.Response{
					Header:        http.Header{"Content-Encoding": []string{"gzip"}},
					ContentLength: 5000,
				},
				want: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := shouldCompress(tt.response); got != tt.want {
					t.Errorf("shouldCompress() = %v, want %v", got, tt.want)
				}
			})
		}
	})
}

func TestWriteResponseToStream(t *testing.T) {
	tests := []struct {
		name     string
		response *http.Response
		wantErr  bool
	}{
		{
			name: "simple response",
			response: &http.Response{
				StatusCode:    200,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				ContentLength: 5,
				Body:          io.NopCloser(strings.NewReader("hello")),
			},
			wantErr: false,
		},
		{
			name: "response with large body",
			response: &http.Response{
				StatusCode:    200,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
				ContentLength: 1000,
				Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", 1000))),
			},
			wantErr: false,
		},
		{
			name: "response without body",
			response: &http.Response{
				StatusCode: 204,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     http.Header{},
				Body:       nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeResponseToStream(&buf, tt.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeResponseToStream() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify we can read it back
			resp, err := readResponseFromStream(&buf)
			if err != nil {
				t.Errorf("readResponseFromStream() error = %v", err)
				return
			}

			if resp.StatusCode != tt.response.StatusCode {
				t.Errorf("StatusCode = %v, want %v", resp.StatusCode, tt.response.StatusCode)
			}

			if resp.Proto != tt.response.Proto {
				t.Errorf("Proto = %v, want %v", resp.Proto, tt.response.Proto)
			}
		})
	}
}

func TestWriteResponseToStreamChunked(t *testing.T) {
	tests := []struct {
		name     string
		response *http.Response
		wantErr  bool
	}{
		{
			name: "chunked response",
			response: &http.Response{
				StatusCode:    200,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				ContentLength: -1, // Chunked
				Body:          io.NopCloser(strings.NewReader("hello world")),
			},
			wantErr: false,
		},
		{
			name: "large chunked response",
			response: &http.Response{
				StatusCode:    200,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"application/json"}},
				ContentLength: -1,
				Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", 50000))),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create expected data before response is consumed
			var expectedData []byte
			if tt.response.Body != nil {
				expectedData, _ = io.ReadAll(tt.response.Body)
				// Reset the body for the test
				tt.response.Body = io.NopCloser(strings.NewReader(string(expectedData)))
			}

			var buf bytes.Buffer
			err := writeResponseToStreamChunked(&buf, tt.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeResponseToStreamChunked() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify we can read it back
			resp, err := readResponseFromStreamChunked(&buf)
			if err != nil {
				t.Errorf("readResponseFromStreamChunked() error = %v", err)
				return
			}

			if resp.StatusCode != tt.response.StatusCode {
				t.Errorf("StatusCode = %v, want %v", resp.StatusCode, tt.response.StatusCode)
			}

			// Read the body to verify content
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("ReadAll() error = %v", err)
				return
			}

			if string(body) != string(expectedData) {
				t.Errorf("Body = %v, want %v", string(body), string(expectedData))
			}
		})
	}
}

func TestCreateResponseStream(t *testing.T) {
	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		ContentLength: 5,
		Body:          io.NopCloser(strings.NewReader("hello")),
	}

	stream, err := createResponseStream(resp)
	if err != nil {
		t.Errorf("createResponseStream() error = %v", err)
		return
	}

	// Read the stream back
	readResp, err := readResponseFromStream(stream)
	if err != nil {
		t.Errorf("readResponseFromStream() error = %v", err)
		return
	}

	if readResp.StatusCode != resp.StatusCode {
		t.Errorf("StatusCode = %v, want %v", readResp.StatusCode, resp.StatusCode)
	}
}

func TestCreateResponseStreamChunked(t *testing.T) {
	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		ContentLength: -1,
		Body:          io.NopCloser(strings.NewReader("hello world")),
	}

	stream, err := createResponseStreamChunked(resp)
	if err != nil {
		t.Errorf("createResponseStreamChunked() error = %v", err)
		return
	}

	// Read the stream back
	readResp, err := readResponseFromStreamChunked(stream)
	if err != nil {
		t.Errorf("readResponseFromStreamChunked() error = %v", err)
		return
	}

	if readResp.StatusCode != resp.StatusCode {
		t.Errorf("StatusCode = %v, want %v", readResp.StatusCode, resp.StatusCode)
	}
}

func TestStreamingWriter(t *testing.T) {
	var buf bytes.Buffer
	writer := &StreamingWriter{
		writer:     &buf,
		chunkSize:  defaultChunkSize,
		compressed: false,
		buffer:     make([]byte, defaultChunkSize),
	}

	testData := "hello world"
	n, err := writer.Write([]byte(testData))
	if err != nil {
		t.Errorf("Write() error = %v", err)
		return
	}

	if n != len(testData) {
		t.Errorf("Write() wrote %v bytes, want %v", n, len(testData))
	}

	totalBytes, chunksWritten := writer.GetStats()
	if totalBytes != int64(len(testData)) {
		t.Errorf("GetStats() totalBytes = %v, want %v", totalBytes, len(testData))
	}

	if chunksWritten != 1 {
		t.Errorf("GetStats() chunksWritten = %v, want 1", chunksWritten)
	}
}

func TestStreamingReader(t *testing.T) {
	testData := "hello world"
	var buf bytes.Buffer
	buf.WriteString(testData)

	reader := &StreamingReader{
		reader:     &buf,
		chunkSize:  defaultChunkSize,
		compressed: false,
		buffer:     make([]byte, defaultChunkSize),
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		t.Errorf("ReadAll() error = %v", err)
		return
	}

	if string(body) != testData {
		t.Errorf("Body = %v, want %v", string(body), testData)
	}

	totalBytes, chunksRead := reader.GetStats()
	if totalBytes != int64(len(testData)) {
		t.Errorf("GetStats() totalBytes = %v, want %v", totalBytes, len(testData))
	}

	// StreamingReader may read in multiple chunks depending on buffer size
	if chunksRead < 1 {
		t.Errorf("GetStats() chunksRead = %v, want >= 1", chunksRead)
	}
}

// Benchmark tests
func BenchmarkWriteChunkedBody(b *testing.B) {
	b.ReportAllocs()
	testData := strings.Repeat("x", 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		writeChunkedBody(&buf, strings.NewReader(testData))
	}
}

func BenchmarkChunkedReader(b *testing.B) {
	b.ReportAllocs()
	testData := strings.Repeat("x", 1000)
	var buf bytes.Buffer
	writeChunkedBody(&buf, strings.NewReader(testData))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(buf.Bytes())
		chunkedReader := &chunkedReader{reader: reader}
		io.ReadAll(chunkedReader)
	}
}

func BenchmarkStreamingWriter(b *testing.B) {
	b.ReportAllocs()
	var buf bytes.Buffer
	writer := &StreamingWriter{
		writer:     &buf,
		chunkSize:  defaultChunkSize,
		compressed: false,
		buffer:     make([]byte, defaultChunkSize),
	}

	testData := []byte(strings.Repeat("x", 1000))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer.Write(testData)
		buf.Reset()
	}
}

func BenchmarkStreamingReader(b *testing.B) {
	b.ReportAllocs()
	testData := strings.Repeat("x", 1000)
	var buf bytes.Buffer
	buf.WriteString(testData)

	reader := &StreamingReader{
		reader:     &buf,
		chunkSize:  defaultChunkSize,
		compressed: false,
		buffer:     make([]byte, defaultChunkSize),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		io.ReadAll(reader)
		buf.Reset()
		buf.WriteString(testData)
	}
}

// Additional comprehensive tests
func TestLargeResponseHandling(t *testing.T) {
	// Test with various large response sizes
	sizes := []int{1024, 10240, 102400} // 1KB, 10KB, 100KB

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			// Create large response
			largeData := strings.Repeat("x", size)
			resp := &http.Response{
				StatusCode:    200,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				ContentLength: int64(size),
				Body:          io.NopCloser(strings.NewReader(largeData)),
			}

			// Test streaming write
			start := time.Now()
			var buf bytes.Buffer
			err := writeResponseToStream(&buf, resp)
			writeDuration := time.Since(start)

			if err != nil {
				t.Errorf("writeResponseToStream() error = %v", err)
				return
			}

			// Test streaming read
			start = time.Now()
			readResp, err := readResponseFromStream(&buf)
			readDuration := time.Since(start)

			if err != nil {
				t.Errorf("readResponseFromStream() error = %v", err)
				return
			}

			// Verify content
			body, err := io.ReadAll(readResp.Body)
			if err != nil {
				t.Errorf("ReadAll() error = %v", err)
				return
			}

			if len(body) != size {
				t.Errorf("Body length = %v, want %v", len(body), size)
			}

			if string(body) != largeData {
				t.Errorf("Body content mismatch")
			}

			t.Logf("Size: %d bytes, Write: %v, Read: %v", size, writeDuration, readDuration)
		})
	}
}

func TestConcurrentStreaming(t *testing.T) {
	// Test concurrent streaming operations
	numGoroutines := 5
	responseSize := 1024 * 1024 // 1MB per response

	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			data := strings.Repeat(string(rune('a'+id)), responseSize)
			resp := &http.Response{
				StatusCode:    200,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				ContentLength: int64(len(data)),
				Body:          io.NopCloser(strings.NewReader(data)),
			}

			// Write and read back
			var buf bytes.Buffer
			if err := writeResponseToStream(&buf, resp); err != nil {
				done <- err
				return
			}

			readResp, err := readResponseFromStream(&buf)
			if err != nil {
				done <- err
				return
			}

			body, err := io.ReadAll(readResp.Body)
			if err != nil {
				done <- err
				return
			}

			if len(body) != len(data) {
				done <- fmt.Errorf("goroutine %d: body length mismatch", id)
				return
			}

			done <- nil
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Concurrent streaming error: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Errorf("Concurrent streaming timeout")
			return
		}
	}
}

func TestStreamingWriterPerformance(t *testing.T) {
	// Test StreamingWriter performance
	var buf bytes.Buffer
	writer := &StreamingWriter{
		writer:     &buf,
		chunkSize:  defaultChunkSize,
		compressed: false,
		buffer:     make([]byte, defaultChunkSize),
	}

	// Write large amount of data
	dataSize := 1024 * 1024 // 1MB
	chunkSize := 64 * 1024  // 64KB chunks
	data := make([]byte, chunkSize)

	start := time.Now()
	for i := 0; i < dataSize/chunkSize; i++ {
		_, err := writer.Write(data)
		if err != nil {
			t.Errorf("Write() error = %v", err)
			return
		}
	}
	duration := time.Since(start)

	totalBytes, chunksWritten := writer.GetStats()
	if totalBytes != int64(dataSize) {
		t.Errorf("Total bytes = %v, want %v", totalBytes, dataSize)
	}

	t.Logf("StreamingWriter: %d bytes in %v (%d chunks)", totalBytes, duration, chunksWritten)
}

func TestStreamingReaderPerformance(t *testing.T) {
	// Test StreamingReader performance
	dataSize := 1024 * 1024 // 1MB
	data := make([]byte, dataSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	reader := &StreamingReader{
		reader:     bytes.NewReader(data),
		chunkSize:  defaultChunkSize,
		compressed: false,
		buffer:     make([]byte, defaultChunkSize),
	}

	start := time.Now()
	readData, err := io.ReadAll(reader)
	duration := time.Since(start)

	if err != nil {
		t.Errorf("ReadAll() error = %v", err)
		return
	}

	if len(readData) != dataSize {
		t.Errorf("Read data length = %v, want %v", len(readData), dataSize)
	}

	totalBytes, chunksRead := reader.GetStats()
	if totalBytes != int64(dataSize) {
		t.Errorf("Total bytes = %v, want %v", totalBytes, dataSize)
	}

	t.Logf("StreamingReader: %d bytes in %v (%d chunks)", totalBytes, duration, chunksRead)
}

// Benchmark tests for performance validation
func BenchmarkWriteResponseToStream(b *testing.B) {
	b.ReportAllocs()
	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		ContentLength: 10000,
		Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", 10000))),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		writeResponseToStream(&buf, resp)
	}
}

func BenchmarkWriteResponseToStreamChunked(b *testing.B) {
	b.ReportAllocs()
	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		ContentLength: -1,
		Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", 10000))),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		writeResponseToStreamChunked(&buf, resp)
	}
}

func BenchmarkReadResponseFromStream(b *testing.B) {
	b.ReportAllocs()
	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		ContentLength: 10000,
		Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", 10000))),
	}

	var buf bytes.Buffer
	writeResponseToStream(&buf, resp)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(buf.Bytes())
		readResponseFromStream(reader)
	}
}

func BenchmarkConcurrentStreaming(b *testing.B) {
	b.ReportAllocs()
	data := strings.Repeat("x", 1024*1024) // 1MB
	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		ContentLength: int64(len(data)),
		Body:          io.NopCloser(strings.NewReader(data)),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var buf bytes.Buffer
			writeResponseToStream(&buf, resp)
		}
	})
}
