// Package compressor handles HTTP response compression and decompression (gzip, brotli, zstd, deflate).
package compressor

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
)

// Compressor performs the compressor operation.
func Compressor(compressionLevel int) func(http.Handler) http.Handler {
	// Create compressor once and reuse
	c := middleware.NewCompressor(compressionLevel)
	c.SetEncoder("deflate", func(w io.Writer, level int) io.Writer {
		slog.Debug("creating deflate writer",
			logging.FieldCaller, "compressor:Compressor",
			"level", level)
		wr, err := flate.NewWriter(w, level)
		if err != nil {
			slog.Error("failed to create deflate writer",
				logging.FieldError, err)
			return w
		}
		return wr
	})
	c.SetEncoder("gzip", func(w io.Writer, level int) io.Writer {
		slog.Debug("creating gzip writer",
			logging.FieldCaller, "compressor:Compressor",
			"level", level)
		wr, err := gzip.NewWriterLevel(w, level)
		if err != nil {
			slog.Error("failed to create gzip writer",
				logging.FieldError, err)
			return w
		}
		return wr
	})
	c.SetEncoder("zstd", func(w io.Writer, level int) io.Writer {
		slog.Debug("creating zstd writer",
			logging.FieldCaller, "compressor:Compressor")
		wr, err := zstd.NewWriter(w)
		if err != nil {
			slog.Error("failed to create zstd writer",
				logging.FieldError, err)
			return w
		}
		return wr
	})
	c.SetEncoder("snappy", func(w io.Writer, level int) io.Writer {
		slog.Debug("creating snappy writer",
			logging.FieldCaller, "compressor:Compressor")
		return snappy.NewBufferedWriter(w)
	})
	c.SetEncoder("br", func(w io.Writer, level int) io.Writer {
		slog.Debug("creating brotli writer",
			logging.FieldCaller, "compressor:Compressor",
			"level", level)
		return brotli.NewWriterLevel(w, level)
	})
	c.SetEncoder("zlib", func(w io.Writer, level int) io.Writer {
		slog.Debug("creating zlib writer",
			logging.FieldCaller, "compressor:Compressor",
			"level", level)
		wr, err := zlib.NewWriterLevel(w, level)
		if err != nil {
			slog.Error("failed to create zlib writer",
				logging.FieldError, err)
			return w
		}
		return wr
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip compression for WebSocket upgrade requests
			// WebSocket connections use their own compression (permessage-deflate)
			// and chi's compressor wraps the response writer without implementing http.Hijacker
			if isWebSocketUpgrade(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Wrap the response writer to consolidate Vary headers
			vw := &varyConsolidator{ResponseWriter: w}
			c.Handler(next).ServeHTTP(vw, r)
		})
	}
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// varyConsolidator wraps http.ResponseWriter to consolidate duplicate Vary headers
type varyConsolidator struct {
	http.ResponseWriter
	headersSent bool
}

// consolidateVaryHeaders consolidates duplicate Vary header values
func (v *varyConsolidator) consolidateVaryHeaders() {
	varyValues := v.ResponseWriter.Header().Values("Vary")
	if len(varyValues) <= 1 {
		// No duplicates to consolidate
		return
	}

	// Collect all unique Vary values
	seen := make(map[string]bool)
	var consolidated []string

	for _, val := range varyValues {
		// Split comma-separated values
		parts := strings.Split(val, ",")
		for _, part := range parts {
			trimmed := strings.TrimSpace(strings.ToLower(part))
			if trimmed != "" && !seen[trimmed] {
				seen[trimmed] = true
				// Preserve original case for the first occurrence
				consolidated = append(consolidated, strings.TrimSpace(part))
			}
		}
	}

	// Update the header with consolidated values
	v.ResponseWriter.Header().Del("Vary")
	if len(consolidated) > 0 {
		// Join all values with comma
		v.ResponseWriter.Header().Set("Vary", strings.Join(consolidated, ", "))
	}
}

// Write writes the header to the underlying response writer
func (v *varyConsolidator) Write(b []byte) (int, error) {
	if !v.headersSent {
		v.consolidateVaryHeaders()
		v.headersSent = true
	}
	return v.ResponseWriter.Write(b)
}

// WriteHeader writes the header to the underlying response writer
func (v *varyConsolidator) WriteHeader(statusCode int) {
	if !v.headersSent {
		v.consolidateVaryHeaders()
		v.headersSent = true
	}
	v.ResponseWriter.WriteHeader(statusCode)
}

// Flush flushes the underlying response writer if it supports http.Flusher
func (v *varyConsolidator) Flush() {
	if f, ok := v.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker to support WebSocket connections
func (v *varyConsolidator) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := v.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}
