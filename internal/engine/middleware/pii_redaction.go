// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/internal/security/pii"
)

// PIIRedactionConfig configures the PII redaction middleware.
type PIIRedactionConfig struct {
	Enabled   bool     `json:"enabled"`
	Detectors []string `json:"detectors,omitempty"` // Detector names to enable; empty = all defaults
	Mode      string   `json:"mode,omitempty"`      // "mask" (default), "hash", "remove"
	ApplyTo   []string `json:"apply_to,omitempty"`  // "request_body", "response_body", "headers", "logs"
}

// PIIRedactionMiddleware creates middleware that scans and redacts PII from
// request and response bodies according to the given configuration.
func PIIRedactionMiddleware(cfg PIIRedactionConfig) func(http.Handler) http.Handler {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}

	if cfg.Mode == "" {
		cfg.Mode = pii.ModeMask
	}

	applySet := make(map[string]bool, len(cfg.ApplyTo))
	for _, a := range cfg.ApplyTo {
		applySet[a] = true
	}
	// Default: apply to request and response bodies if nothing specified.
	if len(applySet) == 0 {
		applySet["request_body"] = true
		applySet["response_body"] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Redact request body
			if applySet["request_body"] && r.Body != nil && r.ContentLength != 0 {
				body, err := io.ReadAll(io.LimitReader(r.Body, pii.DefaultMaxBodySize))
				r.Body.Close()
				if err == nil && len(body) > 0 {
					redacted := pii.RedactBytes(body, cfg.Detectors, cfg.Mode)
					if !bytes.Equal(redacted, body) {
						slog.Debug("pii redaction applied to request body",
							"path", r.URL.Path,
							"mode", cfg.Mode)
					}
					r.Body = io.NopCloser(bytes.NewReader(redacted))
					r.ContentLength = int64(len(redacted))
					r.Header.Set("Content-Length", strconv.Itoa(len(redacted)))
				} else {
					r.Body = io.NopCloser(bytes.NewReader(body))
				}
			}

			// Redact request headers
			if applySet["headers"] {
				redactHeaders(r.Header, cfg.Detectors, cfg.Mode)
			}

			// Wrap response writer if we need to redact response body
			if applySet["response_body"] {
				rw := &piiRedactionResponseWriter{
					ResponseWriter: w,
					detectors:      cfg.Detectors,
					mode:           cfg.Mode,
					request:        r,
				}
				next.ServeHTTP(rw, r)
				rw.flush()
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// redactHeaders scans header values for PII and replaces them in-place.
func redactHeaders(h http.Header, detectors []string, mode string) {
	// Skip standard headers that are not user content.
	skip := map[string]bool{
		"Content-Type":   true,
		"Content-Length": true,
		"Accept":         true,
		"Host":           true,
		"Connection":     true,
		"User-Agent":     true,
	}
	for key, values := range h {
		if skip[key] {
			continue
		}
		for i, v := range values {
			redacted := pii.Redact(v, detectors, mode)
			if redacted != v {
				values[i] = redacted
			}
		}
	}
}

// piiRedactionResponseWriter buffers the response body so PII can be redacted
// before it reaches the client.
type piiRedactionResponseWriter struct {
	http.ResponseWriter
	detectors  []string
	mode       string
	request    *http.Request
	statusCode int
	buf        bytes.Buffer
	flushed    bool
}

// WriteHeader captures the status code without sending it.
func (rw *piiRedactionResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
}

// Write buffers response data for later redaction.
func (rw *piiRedactionResponseWriter) Write(data []byte) (int, error) {
	return rw.buf.Write(data)
}

// flush sends the (possibly redacted) response to the client.
func (rw *piiRedactionResponseWriter) flush() {
	if rw.flushed {
		return
	}
	rw.flushed = true

	body := rw.buf.Bytes()
	statusCode := rw.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	// Skip binary content types.
	ct := rw.Header().Get("Content-Type")
	if isBinaryContentType(ct) {
		rw.ResponseWriter.WriteHeader(statusCode)
		rw.ResponseWriter.Write(body) // nolint: errcheck
		return
	}

	redacted := pii.RedactBytes(body, rw.detectors, rw.mode)
	if !bytes.Equal(redacted, body) {
		rw.Header().Set("Content-Length", strconv.Itoa(len(redacted)))
		slog.Debug("pii redaction applied to response body",
			"path", rw.request.URL.Path,
			"mode", rw.mode)
	}

	rw.ResponseWriter.WriteHeader(statusCode)
	rw.ResponseWriter.Write(redacted) // nolint: errcheck
}

// isBinaryContentType returns true for content types that should not be scanned.
func isBinaryContentType(ct string) bool {
	return strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "video/") ||
		strings.HasPrefix(ct, "audio/") ||
		ct == "application/octet-stream"
}
