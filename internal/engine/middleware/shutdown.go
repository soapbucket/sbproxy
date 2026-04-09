// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/platform/health"
)

// ShutdownMiddleware creates middleware that rejects new requests during graceful shutdown
// and tracks in-flight requests. When the service is shutting down, it immediately returns
// 503 Service Unavailable. Otherwise, it increments the in-flight request counter, processes
// the request, and decrements the counter when done.
func ShutdownMiddleware(healthMgr *health.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if service is shutting down
			if healthMgr.IsShuttingDown() {
				slog.Info("rejecting request during shutdown",
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr)

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Connection", "close")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"status":"service_unavailable","reason":"server_shutting_down"}`))
				return
			}

			// Track this request as in-flight
			healthMgr.IncrementInflight()
			defer healthMgr.DecrementInflight()

			// Process the request
			next.ServeHTTP(w, r)
		})
	}
}

