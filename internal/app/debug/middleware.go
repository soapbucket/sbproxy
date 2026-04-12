// Package debug adds request/response inspection middleware for development and troubleshooting.
package debug

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/version"
)

// debugResponseWriter wraps http.ResponseWriter to inject debug headers
// just before the response status is written. This ensures all debug headers
// added by downstream handlers (e.g., X-Sb-Origin) are included.
type debugResponseWriter struct {
	http.ResponseWriter
	requestData *reqctx.RequestData
	headersSent bool
}

func (d *debugResponseWriter) injectDebugHeaders() {
	if d.headersSent {
		return
	}
	d.headersSent = true

	for key, value := range d.requestData.DebugHeaders {
		d.ResponseWriter.Header().Set(key, value)
	}
	d.ResponseWriter.Header().Set(httputil.HeaderXSbDebug, "true")
	d.ResponseWriter.Header().Set(httputil.HeaderXSbVersion, version.Version)
	if version.BuildHash != "" {
		d.ResponseWriter.Header().Set(httputil.HeaderXSbBuildHash, version.BuildHash)
	}
}

// WriteHeader performs the write header operation on the debugResponseWriter.
func (d *debugResponseWriter) WriteHeader(statusCode int) {
	d.injectDebugHeaders()
	d.ResponseWriter.WriteHeader(statusCode)
}

// Write performs the write operation on the debugResponseWriter.
func (d *debugResponseWriter) Write(b []byte) (int, error) {
	d.injectDebugHeaders()
	return d.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming responses (SSE).
func (d *debugResponseWriter) Flush() {
	if f, ok := d.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// DebugMiddleware returns HTTP middleware for debug.
func DebugMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestData := reqctx.GetRequestData(r.Context())
		if requestData != nil && requestData.Debug {
			dw := &debugResponseWriter{
				ResponseWriter: w,
				requestData:    requestData,
			}
			next.ServeHTTP(dw, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
