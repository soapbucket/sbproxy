// Package compression implements proxy-level response compression (RFC 9110 Section 8.4).
package compression

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Config controls proxy-level response compression (RFC 9110 Section 8.4)
type Config struct {
	// Enable proxy-level response compression.
	// Default: false (rely on upstream compression)
	Enable bool `json:"enable,omitempty" yaml:"enable,omitempty"`

	// Supported algorithms in preference order.
	// Default: ["gzip", "br"]
	Algorithms []string `json:"algorithms,omitempty" yaml:"algorithms,omitempty"`

	// Minimum response body size in bytes to trigger compression.
	// Default: 1024
	MinSize int `json:"min_size,omitempty" yaml:"min_size,omitempty"`

	// Content types to exclude from compression (already compressed formats).
	// Default: ["image/*", "video/*", "audio/*", "application/zip", "application/gzip"]
	ExcludeContentTypes []string `json:"exclude_content_types,omitempty" yaml:"exclude_content_types,omitempty"`

	// Compression level (1-9, higher = better compression, more CPU).
	// Default: 6
	Level int `json:"level,omitempty" yaml:"level,omitempty"`
}

// ResponseWriter wraps http.ResponseWriter to compress response bodies.
// Implements RFC 9110 Section 8.4 content encoding at the proxy level.
type ResponseWriter struct {
	http.ResponseWriter
	Writer      io.WriteCloser
	Encoding    string
	WroteHeader bool
	Buf         []byte
	StatusCode  int
	Cfg         *Config
}

var GzipWriterPool = sync.Pool{
	New: func() any {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return w
	},
}

var BrotliWriterPool = sync.Pool{
	New: func() any {
		return brotli.NewWriterLevel(io.Discard, brotli.DefaultCompression)
	},
}

// ShouldCompress checks if the response should be compressed based on content type and size.
func ShouldCompress(contentType string, cfg *Config) bool {
	if contentType == "" {
		return true
	}

	excludeTypes := cfg.ExcludeContentTypes
	if len(excludeTypes) == 0 {
		excludeTypes = []string{
			"image/*", "video/*", "audio/*",
			"application/zip", "application/gzip", "application/x-gzip",
			"application/brotli", "application/zstd",
		}
	}

	for _, exclude := range excludeTypes {
		if strings.HasSuffix(exclude, "/*") {
			prefix := strings.TrimSuffix(exclude, "/*")
			if strings.HasPrefix(contentType, prefix+"/") {
				return false
			}
		} else if strings.EqualFold(contentType, exclude) {
			return false
		}
	}

	return true
}

// SelectEncoding picks the best encoding from Accept-Encoding that we support.
func SelectEncoding(acceptEncoding string, cfg *Config) string {
	if acceptEncoding == "" {
		return ""
	}

	algorithms := cfg.Algorithms
	if len(algorithms) == 0 {
		algorithms = []string{"gzip", "br"}
	}

	// Parse Accept-Encoding and find the best match based on our preference order
	for _, algo := range algorithms {
		if ContainsEncoding(acceptEncoding, algo) {
			if algo == "gzip" || algo == "br" || algo == "zstd" {
				return algo
			}
		}
	}

	return ""
}

// ContainsEncoding checks if the Accept-Encoding header contains a specific encoding.
func ContainsEncoding(header, encoding string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		// Strip quality factor
		if idx := strings.Index(part, ";"); idx >= 0 {
			qPart := strings.TrimSpace(part[idx+1:])
			part = strings.TrimSpace(part[:idx])
			// Skip if quality is 0
			if strings.HasPrefix(qPart, "q=0") && !strings.HasPrefix(qPart, "q=0.") {
				continue
			}
			if qPart == "q=0.0" || qPart == "q=0.00" || qPart == "q=0.000" {
				continue
			}
		}
		if strings.EqualFold(part, encoding) {
			return true
		}
	}
	return false
}

func (w *ResponseWriter) WriteHeader(statusCode int) {
	if w.WroteHeader {
		return
	}
	w.StatusCode = statusCode
	// Don't compress 1xx, 204, 304 responses
	if statusCode < 200 || statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		w.ResponseWriter.WriteHeader(statusCode)
		w.WroteHeader = true
		return
	}

	// Check content type
	ct := w.Header().Get("Content-Type")
	if ct != "" {
		// Extract media type without parameters
		if idx := strings.Index(ct, ";"); idx >= 0 {
			ct = strings.TrimSpace(ct[:idx])
		}
	}

	if !ShouldCompress(ct, w.Cfg) {
		w.Encoding = ""
		w.ResponseWriter.WriteHeader(statusCode)
		w.WroteHeader = true
		return
	}

	// Don't compress if response is already encoded
	if w.Header().Get("Content-Encoding") != "" {
		w.Encoding = ""
		w.ResponseWriter.WriteHeader(statusCode)
		w.WroteHeader = true
		return
	}

	// Defer actual header write until we know body size via Write calls
}

func (w *ResponseWriter) Write(b []byte) (int, error) {
	if !w.WroteHeader && w.StatusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}

	// Already decided not to compress
	if w.WroteHeader {
		if w.Writer != nil {
			return w.Writer.Write(b)
		}
		return w.ResponseWriter.Write(b)
	}

	// Buffer until we know if we should compress
	w.Buf = append(w.Buf, b...)

	minSize := w.Cfg.MinSize
	if minSize <= 0 {
		minSize = 1024
	}

	if len(w.Buf) >= minSize {
		return len(b), w.startCompression()
	}

	return len(b), nil
}

func (w *ResponseWriter) startCompression() error {
	if w.Encoding == "gzip" {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length") // Length changes with compression
		w.Header().Add("Vary", "Accept-Encoding")
		w.ResponseWriter.WriteHeader(w.StatusCode)
		w.WroteHeader = true

		gz := GzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(w.ResponseWriter)
		w.Writer = gz

		_, err := gz.Write(w.Buf)
		w.Buf = nil
		return err
	}

	if w.Encoding == "br" {
		w.Header().Set("Content-Encoding", "br")
		w.Header().Del("Content-Length")
		w.Header().Add("Vary", "Accept-Encoding")
		w.ResponseWriter.WriteHeader(w.StatusCode)
		w.WroteHeader = true

		br := BrotliWriterPool.Get().(*brotli.Writer)
		br.Reset(w.ResponseWriter)
		w.Writer = br

		_, err := br.Write(w.Buf)
		w.Buf = nil
		return err
	}

	if w.Encoding == "zstd" {
		w.Header().Set("Content-Encoding", "zstd")
		w.Header().Del("Content-Length")
		w.Header().Add("Vary", "Accept-Encoding")
		w.ResponseWriter.WriteHeader(w.StatusCode)
		w.WroteHeader = true

		zw, err := zstd.NewWriter(w.ResponseWriter, zstd.WithEncoderLevel(zstd.SpeedDefault))
		if err != nil {
			return err
		}
		w.Writer = zw

		_, err = zw.Write(w.Buf)
		w.Buf = nil
		return err
	}

	// No compression
	w.ResponseWriter.WriteHeader(w.StatusCode)
	w.WroteHeader = true
	if len(w.Buf) > 0 {
		_, err := w.ResponseWriter.Write(w.Buf)
		w.Buf = nil
		return err
	}
	return nil
}

// Close flushes any buffered data and closes the compression writer.
func (w *ResponseWriter) Close() error {
	// Flush any remaining buffered data that didn't reach minSize
	if !w.WroteHeader {
		if w.StatusCode == 0 {
			w.StatusCode = http.StatusOK
		}
		// Body was smaller than minSize, write without compression
		w.Encoding = ""
		w.ResponseWriter.WriteHeader(w.StatusCode)
		w.WroteHeader = true
		if len(w.Buf) > 0 {
			_, _ = w.ResponseWriter.Write(w.Buf)
			w.Buf = nil
		}
		return nil
	}

	if w.Writer != nil {
		err := w.Writer.Close()
		switch v := w.Writer.(type) {
		case *gzip.Writer:
			GzipWriterPool.Put(v)
		case *brotli.Writer:
			BrotliWriterPool.Put(v)
		case *zstd.Encoder:
			// zstd.Encoder is not pooled - created per response
		}
		return err
	}
	return nil
}

// Flush implements http.Flusher
func (w *ResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.Writer != nil {
			switch v := w.Writer.(type) {
			case *gzip.Writer:
				v.Flush()
			case *brotli.Writer:
				v.Flush()
			case *zstd.Encoder:
				v.Flush()
			}
		}
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController compatibility.
func (w *ResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// ReadFrom prevents io.CopyBuffer from bypassing our Write method via io.ReaderFrom.
// Without this, io.CopyBuffer detects io.ReaderFrom on the embedded ResponseWriter
// (e.g., httptest.ResponseRecorder's bytes.Buffer) and skips our Write entirely.
func (w *ResponseWriter) ReadFrom(r io.Reader) (n int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[0:nr])
			n += int64(nw)
			if ew != nil {
				return n, ew
			}
			if nr != nw {
				return n, io.ErrShortWrite
			}
		}
		if er == io.EOF {
			return n, nil
		}
		if er != nil {
			return n, er
		}
	}
}
