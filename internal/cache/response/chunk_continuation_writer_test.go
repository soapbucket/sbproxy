package responsecache

import (
	"net/http/httptest"
	"testing"
)

func TestChunkContinuationWriter(t *testing.T) {
	t.Run("writes after offset", func(t *testing.T) {
		w := httptest.NewRecorder()

		// Simulate 100 bytes already written (cached chunk)
		cachedData := make([]byte, 100)
		for i := range cachedData {
			cachedData[i] = byte('A')
		}
		w.Write(cachedData)

		// Create continuation writer with 100 byte offset
		crw := &ChunkContinuationWriter{
			rw:             w,
			offset:         100,
			flusher:        w,
			headersWritten: true,
		}

		// Write data that includes the cached part + new data
		fullData := make([]byte, 200)
		for i := range fullData {
			if i < 100 {
				fullData[i] = byte('A') // Cached part
			} else {
				fullData[i] = byte('B') // New part
			}
		}

		n, err := crw.Write(fullData)
		if err != nil {
			t.Fatalf("Write() error = %v", err)
		}

		if n != 200 {
			t.Errorf("Write() returned %d, want 200", n)
		}

		// Check that only new data was written (not duplicate)
		body := w.Body.Bytes()
		if len(body) != 200 {
			t.Errorf("Body length = %d, want 200", len(body))
		}

		// First 100 should be 'A' (original cached)
		// Last 100 should be 'B' (new data)
		for i := 0; i < 100; i++ {
			if body[i] != 'A' {
				t.Errorf("Body[%d] = %c, want 'A'", i, body[i])
				break
			}
		}
		for i := 100; i < 200; i++ {
			if body[i] != 'B' {
				t.Errorf("Body[%d] = %c, want 'B'", i, body[i])
				break
			}
		}
	})

	t.Run("skips fully cached data", func(t *testing.T) {
		w := httptest.NewRecorder()

		// Simulate 100 bytes already written
		cachedData := make([]byte, 100)
		w.Write(cachedData)

		crw := &ChunkContinuationWriter{
			rw:             w,
			offset:         100,
			flusher:        w,
			headersWritten: true,
		}

		// Write only data that was already cached
		data := make([]byte, 50)
		n, err := crw.Write(data)
		if err != nil {
			t.Fatalf("Write() error = %v", err)
		}

		if n != 50 {
			t.Errorf("Write() returned %d, want 50", n)
		}

		// Body should still be 100 (nothing new written)
		body := w.Body.Bytes()
		if len(body) != 100 {
			t.Errorf("Body length = %d, want 100 (no new data should be written)", len(body))
		}

		// Offset should be reduced
		if crw.offset != 50 {
			t.Errorf("offset = %d, want 50", crw.offset)
		}
	})

	t.Run("writes all data when offset is zero", func(t *testing.T) {
		w := httptest.NewRecorder()

		crw := &ChunkContinuationWriter{
			rw:             w,
			offset:         0, // No cached data
			flusher:        w,
			headersWritten: true,
		}

		data := []byte("Hello, World!")
		n, err := crw.Write(data)
		if err != nil {
			t.Fatalf("Write() error = %v", err)
		}

		if n != len(data) {
			t.Errorf("Write() returned %d, want %d", n, len(data))
		}

		body := w.Body.String()
		if body != "Hello, World!" {
			t.Errorf("Body = %q, want %q", body, "Hello, World!")
		}
	})

	t.Run("Header returns empty map", func(t *testing.T) {
		w := httptest.NewRecorder()

		crw := &ChunkContinuationWriter{
			rw:             w,
			offset:         0,
			flusher:        w,
			headersWritten: true,
		}

		headers := crw.Header()
		if len(headers) != 0 {
			t.Errorf("Header() returned non-empty map, want empty (headers already sent)")
		}

		// Setting headers should not affect underlying writer
		headers.Set("X-Test", "value")
		if w.Header().Get("X-Test") != "" {
			t.Error("Setting headers on continuation writer should not affect underlying writer")
		}
	})

	t.Run("WriteHeader ignores status", func(t *testing.T) {
		w := httptest.NewRecorder()

		crw := &ChunkContinuationWriter{
			rw:             w,
			offset:         0,
			flusher:        w,
			headersWritten: false,
		}

		// Should not panic or affect underlying writer
		crw.WriteHeader(404)

		if !crw.headersWritten {
			t.Error("headersWritten should be true after WriteHeader")
		}

		// Underlying writer should still be 200 (default)
		if w.Code != 200 {
			t.Errorf("Underlying writer status = %d, want 200 (unchanged)", w.Code)
		}
	})

	t.Run("Flush calls underlying flusher", func(t *testing.T) {
		w := httptest.NewRecorder()

		crw := &ChunkContinuationWriter{
			rw:             w,
			offset:         0,
			flusher:        w,
			headersWritten: true,
		}

		// Should not panic
		crw.Flush()
	})
}
