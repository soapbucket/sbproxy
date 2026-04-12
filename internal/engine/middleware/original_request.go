// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/httpkit/zerocopy"
)

// CaptureOriginalRequest captures the original request before any modifications
// This middleware should be placed early in the chain, right after RequestData creation
// Performance: ~50µs overhead for small bodies, significant allocation reduction
func CaptureOriginalRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rd := reqctx.GetRequestData(r.Context())
		if rd == nil {
			// RequestData not in context, skip capture
			next.ServeHTTP(w, r)
			return
		}

		// Read and buffer body for capture
		var body []byte
		if r.Body != nil && r.ContentLength != 0 {
			// Use pooled buffers for reading body
			bl, err := zerocopy.ReadAllToBufferList(r.Body)
			if err != nil {
				slog.Warn("failed to read request body for capture",
					"error", err,
					"request_id", rd.ID)
				// Continue without body capture
				next.ServeHTTP(w, r)
				return
			}
			defer bl.Release()

			body = bl.Bytes()

			// Restore body for downstream handlers
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		// Check if content type is JSON
		contentType := r.Header.Get("Content-Type")
		isJSON := strings.Contains(strings.ToLower(contentType), "application/json")

		// Store original request data using pooled objects.
		// Headers and URL are lazily computed on first access via SetRequest.
		orig := reqctx.OriginalRequestDataPool.Get().(*reqctx.OriginalRequestData)
		orig.Method = r.Method
		orig.Path = r.URL.Path
		orig.RawQuery = r.URL.RawQuery
		orig.Body = body
		orig.IsJSON = isJSON
		orig.ContentType = contentType
		orig.RemoteAddr = r.RemoteAddr
		orig.SetRequest(r)

		rd.OriginalRequest = orig

		slog.Debug("captured original request",
			"request_id", rd.ID,
			"method", r.Method,
			"path", r.URL.Path,
			"body_size", len(body),
			"is_json", isJSON)

		next.ServeHTTP(w, r)
	})
}

