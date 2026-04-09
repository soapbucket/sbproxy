// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
)

// compressedResponseWriter wraps http.ResponseWriter to compress response bodies.
// Implements RFC 9110 Section 8.4 content encoding at the proxy level.
type compressedResponseWriter struct {
	http.ResponseWriter
	writer      io.WriteCloser
	encoding    string
	wroteHeader bool
	minSize     int
	buf         []byte
	statusCode  int
	config      *CompressionConfig
}

var gzipWriterPool = sync.Pool{
	New: func() any {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return w
	},
}

var brotliWriterPool = sync.Pool{
	New: func() any {
		return brotli.NewWriterLevel(io.Discard, brotli.DefaultCompression)
	},
}

// shouldCompress checks if the response should be compressed based on content type and size.
func shouldCompress(contentType string, cfg *CompressionConfig) bool {
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

// selectEncoding picks the best encoding from Accept-Encoding that we support.
func selectEncoding(acceptEncoding string, cfg *CompressionConfig) string {
	if acceptEncoding == "" {
		return ""
	}

	algorithms := cfg.Algorithms
	if len(algorithms) == 0 {
		algorithms = []string{"gzip", "br"}
	}

	// Parse Accept-Encoding and find the best match based on our preference order
	for _, algo := range algorithms {
		if containsEncoding(acceptEncoding, algo) {
			if algo == "gzip" || algo == "br" {
				return algo
			}
		}
	}

	return ""
}

// containsEncoding checks if the Accept-Encoding header contains a specific encoding.
func containsEncoding(header, encoding string) bool {
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

func (w *compressedResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.statusCode = statusCode
	// Don't compress 1xx, 204, 304 responses
	if statusCode < 200 || statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		w.ResponseWriter.WriteHeader(statusCode)
		w.wroteHeader = true
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

	if !shouldCompress(ct, w.config) {
		w.encoding = ""
		w.ResponseWriter.WriteHeader(statusCode)
		w.wroteHeader = true
		return
	}

	// Don't compress if response is already encoded
	if w.Header().Get("Content-Encoding") != "" {
		w.encoding = ""
		w.ResponseWriter.WriteHeader(statusCode)
		w.wroteHeader = true
		return
	}

	// Defer actual header write until we know body size via Write calls
}

func (w *compressedResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader && w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}

	// Already decided not to compress
	if w.wroteHeader {
		if w.writer != nil {
			return w.writer.Write(b)
		}
		return w.ResponseWriter.Write(b)
	}

	// Buffer until we know if we should compress
	w.buf = append(w.buf, b...)

	minSize := w.config.MinSize
	if minSize <= 0 {
		minSize = 1024
	}

	if len(w.buf) >= minSize {
		return len(b), w.startCompression()
	}

	return len(b), nil
}

func (w *compressedResponseWriter) startCompression() error {
	if w.encoding == "gzip" {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length") // Length changes with compression
		w.Header().Add("Vary", "Accept-Encoding")
		w.ResponseWriter.WriteHeader(w.statusCode)
		w.wroteHeader = true

		gz := gzipWriterPool.Get().(*gzip.Writer)
		level := w.config.Level
		if level <= 0 {
			level = gzip.DefaultCompression
		}
		gz.Reset(w.ResponseWriter)
		w.writer = gz

		_, err := gz.Write(w.buf)
		w.buf = nil
		return err
	}

	if w.encoding == "br" {
		w.Header().Set("Content-Encoding", "br")
		w.Header().Del("Content-Length")
		w.Header().Add("Vary", "Accept-Encoding")
		w.ResponseWriter.WriteHeader(w.statusCode)
		w.wroteHeader = true

		br := brotliWriterPool.Get().(*brotli.Writer)
		level := w.config.Level
		if level <= 0 {
			level = brotli.DefaultCompression
		}
		br.Reset(w.ResponseWriter)
		w.writer = br

		_, err := br.Write(w.buf)
		w.buf = nil
		return err
	}

	// No compression
	w.ResponseWriter.WriteHeader(w.statusCode)
	w.wroteHeader = true
	if len(w.buf) > 0 {
		_, err := w.ResponseWriter.Write(w.buf)
		w.buf = nil
		return err
	}
	return nil
}

// Close flushes any buffered data and closes the compression writer.
func (w *compressedResponseWriter) Close() error {
	// Flush any remaining buffered data that didn't reach minSize
	if !w.wroteHeader {
		if w.statusCode == 0 {
			w.statusCode = http.StatusOK
		}
		// Body was smaller than minSize, write without compression
		w.encoding = ""
		w.ResponseWriter.WriteHeader(w.statusCode)
		w.wroteHeader = true
		if len(w.buf) > 0 {
			w.ResponseWriter.Write(w.buf)
			w.buf = nil
		}
		return nil
	}

	if w.writer != nil {
		err := w.writer.Close()
		switch v := w.writer.(type) {
		case *gzip.Writer:
			gzipWriterPool.Put(v)
		case *brotli.Writer:
			brotliWriterPool.Put(v)
		}
		return err
	}
	return nil
}

// Flush implements http.Flusher
func (w *compressedResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.writer != nil {
			switch v := w.writer.(type) {
			case *gzip.Writer:
				v.Flush()
			case *brotli.Writer:
				v.Flush()
			}
		}
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController compatibility.
func (w *compressedResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// ReadFrom prevents io.CopyBuffer from bypassing our Write method via io.ReaderFrom.
// Without this, io.CopyBuffer detects io.ReaderFrom on the embedded ResponseWriter
// (e.g., httptest.ResponseRecorder's bytes.Buffer) and skips our Write entirely.
func (w *compressedResponseWriter) ReadFrom(r io.Reader) (n int64, err error) {
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
