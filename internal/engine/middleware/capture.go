// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/app/capture"
	celutil "github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// CaptureMiddleware creates per-request middleware that captures HTTP exchanges.
// It wraps the ResponseWriter with a Recorder, captures the request body (with limits),
// and pushes the completed Exchange to the capture Manager in a non-blocking manner.
func CaptureMiddleware(mgr *capture.Manager, cfg *reqctx.TrafficCaptureConfig, hostname string) func(http.Handler) http.Handler {
	parsed := config.ParseTrafficCaptureConfig(cfg)

	if !parsed.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	// Compile CEL filter expression once during middleware creation.
	var celFilter celutil.Matcher
	if parsed.Filter != "" {
		var err error
		celFilter, err = celutil.NewMatcher(parsed.Filter)
		if err != nil {
			slog.Warn("failed to compile capture CEL filter expression, capture will proceed without filtering",
				"hostname", hostname, "filter", parsed.Filter, "error", err)
		}
	}

	// Log warnings for degraded capture configurations
	slog.Info("traffic capture enabled",
		"hostname", hostname,
		"sample_rate", parsed.SampleRate,
		"max_body_size", parsed.MaxBodySize,
		"retention", parsed.Retention,
		"has_filter", celFilter != nil)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Sampling: skip this request based on sample_rate
			if parsed.SampleRate < 1.0 && rand.Float64() > parsed.SampleRate {
				next.ServeHTTP(w, r)
				return
			}

			// CEL filter: if configured, evaluate the expression against request context.
			// If expression evaluates to false, skip capture for this request.
			// On evaluation error, log and skip capture (fail-open for observability).
			if celFilter != nil {
				if !celFilter.Match(r) {
					next.ServeHTTP(w, r)
					return
				}
			}

			startTime := time.Now()

			// Acquire exchange from pool
			exchange := mgr.AcquireExchange()

			// Capture request
			captureRequest(r, exchange, parsed.MaxBodySize)

			// Wrap the response writer with a recorder
			rec := acquireRecorder(w, parsed.MaxBodySize)
			defer releaseRecorder(rec)

			// Serve the request with the recording writer
			next.ServeHTTP(rec, r)

			// Capture response
			exchange.Duration = time.Since(startTime).Microseconds()
			exchange.Response = reqctx.CapturedResponse{
				StatusCode:  rec.statusCode,
				Headers:     rec.Header().Clone(),
				Body:        rec.capturedBody(),
				BodySize:    rec.bodySize,
				Truncated:   rec.truncated,
				ContentType: rec.Header().Get("Content-Type"),
			}

			// Add metadata
			if requestData := reqctx.GetRequestData(r.Context()); requestData != nil {
				exchange.Meta["request_id"] = requestData.ID
				if requestData.Config != nil {
					configParams := reqctx.ConfigParams(requestData.Config)
					exchange.Meta["config_id"] = configParams.GetConfigID()
					exchange.Meta["workspace_id"] = configParams.GetWorkspaceID()
				}
			}

			// Non-blocking push to capture manager
			mgr.Push(hostname, exchange, parsed.Retention)
		})
	}
}

// captureRequest captures the request details into the Exchange.
func captureRequest(r *http.Request, exchange *reqctx.Exchange, maxBodySize int64) {
	exchange.Request = reqctx.CapturedRequest{
		Method:      r.Method,
		URL:         r.URL.String(),
		Path:        r.URL.Path,
		Host:        r.Host,
		Protocol:    r.Proto,
		Headers:     r.Header.Clone(),
		ContentType: r.Header.Get("Content-Type"),
		RemoteAddr:  r.RemoteAddr,
	}

	// Determine scheme
	if r.TLS != nil {
		exchange.Request.Scheme = "https"
	} else {
		exchange.Request.Scheme = "http"
	}

	// Capture request body with size limit without changing downstream request semantics.
	if r.Body != nil && r.ContentLength != 0 {
		// If content length is unknown or too large, skip body capture entirely.
		if r.ContentLength < 0 || r.ContentLength > maxBodySize {
			exchange.Request.Truncated = r.ContentLength > maxBodySize
			exchange.Request.BodySize = r.ContentLength
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Debug("failed to read request body for capture", "error", err)
		} else {
			exchange.Request.BodySize = int64(len(body))
			exchange.Request.Body = body
			// Reconstruct the complete body for the next handler.
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}
}

// recorder wraps http.ResponseWriter to capture the response.
type recorder struct {
	http.ResponseWriter
	statusCode  int
	body        bytes.Buffer
	bodySize    int64
	maxBodySize int64
	truncated   bool
	wroteHeader bool
}

var recorderPool = sync.Pool{
	New: func() any {
		return &recorder{}
	},
}

func acquireRecorder(w http.ResponseWriter, maxBodySize int64) *recorder {
	rec := recorderPool.Get().(*recorder)
	rec.ResponseWriter = w
	rec.statusCode = http.StatusOK
	rec.body.Reset()
	rec.bodySize = 0
	rec.maxBodySize = maxBodySize
	rec.truncated = false
	rec.wroteHeader = false
	return rec
}

func releaseRecorder(rec *recorder) {
	rec.ResponseWriter = nil
	rec.body.Reset()
	recorderPool.Put(rec)
}

// WriteHeader performs the write header operation on the recorder.
func (r *recorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// Write performs the write operation on the recorder.
func (r *recorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}

	// Write to the actual response writer first (always)
	n, err := r.ResponseWriter.Write(b)

	// Capture the body with size limit
	r.bodySize += int64(n)
	if !r.truncated && r.body.Len() < int(r.maxBodySize) {
		remaining := int(r.maxBodySize) - r.body.Len()
		if n <= remaining {
			r.body.Write(b[:n])
		} else {
			r.body.Write(b[:remaining])
			r.truncated = true
		}
	} else if !r.truncated {
		r.truncated = true
	}

	return n, err
}

// capturedBody returns the captured body bytes.
func (r *recorder) capturedBody() []byte {
	if r.body.Len() == 0 {
		return nil
	}
	// Make a copy to avoid holding the buffer
	body := make([]byte, r.body.Len())
	copy(body, r.body.Bytes())
	return body
}

// Flush implements http.Flusher.
func (r *recorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker for WebSocket support.
func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, ErrHijackerNotSupported
}

// Unwrap returns the original ResponseWriter.
func (r *recorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
