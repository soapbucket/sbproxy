// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"sync"
	"io"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/app/billing"
	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// MeteringResponseWriter wraps http.ResponseWriter to capture metrics
type MeteringResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	bytesRead    int64
	startTime    time.Time
	cfg          *config.Config
	req          *http.Request
	meter        *billing.Meter
}

var meteringWriterPool = sync.Pool{
	New: func() any { return &MeteringResponseWriter{} },
}

// NewMeteringResponseWriter creates a new metering response writer from the pool
func NewMeteringResponseWriter(w http.ResponseWriter, cfg *config.Config, req *http.Request, meter *billing.Meter) *MeteringResponseWriter {
	mw := meteringWriterPool.Get().(*MeteringResponseWriter)
	mw.ResponseWriter = w
	mw.statusCode = http.StatusOK
	mw.bytesWritten = 0
	mw.bytesRead = 0
	mw.startTime = time.Now()
	mw.cfg = cfg
	mw.req = req
	mw.meter = meter
	return mw
}

// Release returns the writer to the pool
func (m *MeteringResponseWriter) Release() {
	m.ResponseWriter = nil
	m.cfg = nil
	m.req = nil
	m.meter = nil
	meteringWriterPool.Put(m)
}

// WriteHeader captures the status code
func (m *MeteringResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
	m.ResponseWriter.WriteHeader(statusCode)
}

// Write captures bytes written
func (m *MeteringResponseWriter) Write(b []byte) (int, error) {
	n, err := m.ResponseWriter.Write(b)
	m.bytesWritten += int64(n)
	return n, err
}

// Hijack allows middleware to take over the connection
func (m *MeteringResponseWriter) Hijack() (io.ReadWriteCloser, interface{}, error) {
	hijacker, ok := m.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return conn, rw, err
	}
	// Don't record metrics for hijacked connections
	return conn, rw, err
}

// RecordMetrics records the metrics to the meter if it's available
func (m *MeteringResponseWriter) RecordMetrics(bytesIn int64) {
	if m.meter == nil {
		return
	}

	latency := time.Since(m.startTime).Seconds()

	// Convert status code to string for recording
	statusStr := "200"
	if m.statusCode == 0 {
		statusStr = "200"
	} else {
		// Normalize status codes by category
		if m.statusCode >= 500 {
			statusStr = "5xx"
		} else if m.statusCode >= 400 {
			statusStr = "4xx"
		} else if m.statusCode >= 300 {
			statusStr = "3xx"
		} else if m.statusCode >= 200 {
			statusStr = "2xx"
		}
	}

	usageMetric := &billing.UsageMetric{
		WorkspaceID:    m.cfg.WorkspaceID,
		OriginID:       m.cfg.ID,
		OriginHostname: m.cfg.Hostname,
		Status:         statusStr,
		RequestCount:   1,
		BytesIn:        bytesIn,
		BytesOut:       m.bytesWritten,
		BytesBackend:   m.bytesWritten, // Assume all bytes are from backend for now
		BytesFromCache: 0,               // Will be set by cache layer if applicable
		TokensUsed:     0,               // Will be set by AI provider layer if applicable
		ErrorCount:     0,
		Latency:        latency,
		Period:         time.Now().UTC(),
	}

	if m.statusCode >= 400 {
		usageMetric.ErrorCount = 1
	}

	m.meter.Record(usageMetric)

	// Also record to Prometheus metrics
	metric.RecordBillingMetrics(
		m.cfg.WorkspaceID,
		m.cfg.ID,
		m.cfg.Hostname,
		statusStr,
		bytesIn,
		m.bytesWritten,
		m.bytesWritten,
		false, // fromCache - will be set by cache layer
	)
	metric.RecordBillingLatency(m.cfg.WorkspaceID, m.cfg.ID, m.cfg.Hostname, latency)
	metric.HTTPRequestServed(m.statusCode)

	if m.statusCode >= 400 {
		metric.RecordBillingError(m.cfg.WorkspaceID, m.cfg.ID, m.cfg.Hostname, "http_error")
	}
}

// meteringHandler wraps a handler with billing metrics collection.
// Uses a struct instead of closures to avoid per-request allocation.
type meteringHandler struct {
	next  http.Handler
	meter *billing.Meter
	cfg   *config.Config
}

func (h *meteringHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mw := NewMeteringResponseWriter(w, h.cfg, r, h.meter)
	contentLength := int64(0)
	if r.ContentLength > 0 {
		contentLength = r.ContentLength
	}
	h.next.ServeHTTP(mw, r)
	mw.RecordMetrics(contentLength)
	mw.Release()
}

// MeteringMiddlewareWithConfig wraps the request/response to record billing metrics with known config
func MeteringMiddlewareWithConfig(meter *billing.Meter, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &meteringHandler{next: next, meter: meter, cfg: cfg}
	}
}

// MeteringMiddleware wraps the request/response to record billing metrics
func MeteringMiddleware(meter *billing.Meter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get config from context if available
			cfg := &config.Config{
				WorkspaceID: "unknown",
				ID:          "unknown",
				Hostname:    r.Host,
			}

			// Try to get the actual config from context
			if rd := reqctx.GetRequestData(r.Context()); rd != nil {
				params := reqctx.ConfigParams(rd.Config)
				if workspaceID := params.GetWorkspaceID(); workspaceID != "" {
					cfg.WorkspaceID = workspaceID
				}
				if configID := params.GetConfigID(); configID != "" {
					cfg.ID = configID
				}
				if hostname := params.GetConfigHostname(); hostname != "" {
					cfg.Hostname = hostname
				}
			}

			// Create metering response writer
			meteringW := NewMeteringResponseWriter(w, cfg, r, meter)

			// Get request body size if available
			contentLength := int64(0)
			if r.ContentLength > 0 {
				contentLength = r.ContentLength
			}

			// Serve the request
			next.ServeHTTP(meteringW, r)

			// Record metrics and return writer to pool
			meteringW.RecordMetrics(contentLength)
			meteringW.Release()
		})
	}
}
