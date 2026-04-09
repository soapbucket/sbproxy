// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"bufio"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.28.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName = "github.com/soapbucket/sbproxy/internal/engine/middleware"
)

// tracingWriterPool reuses tracingResponseWriter structs to avoid per-request heap allocation.
var tracingWriterPool = sync.Pool{
	New: func() any {
		return &tracingResponseWriter{}
	},
}

func getTracingWriter(w http.ResponseWriter) *tracingResponseWriter {
	tw := tracingWriterPool.Get().(*tracingResponseWriter)
	tw.ResponseWriter = w
	tw.statusCode = http.StatusOK
	tw.written = 0
	return tw
}

func putTracingWriter(tw *tracingResponseWriter) {
	tw.ResponseWriter = nil
	tracingWriterPool.Put(tw)
}

// TracingMiddleware creates middleware that adds OpenTelemetry tracing to requests
func TracingMiddleware(next http.Handler) http.Handler {
	tracer := otel.Tracer(tracerName)
	propagator := otel.GetTextMapPropagator()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get config ID for metrics
		configID := "unknown"
		if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
			configData := reqctx.ConfigParams(requestData.Config)
			if id := configData.GetConfigID(); id != "" {
				configID = id
			}
		}

		// Extract trace context from incoming request
		ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		// Check if trace is sampled
		spanCtx := trace.SpanContextFromContext(ctx)
		traceSampled := spanCtx.IsValid() && spanCtx.IsSampled()

		// Start a new span
		spanStartTime := time.Now()
		// Optimized: Use strings.Builder from pool to reduce allocations
		spanNameBuilder := cacher.GetBuilderWithSize(5 + len(r.Method) + len(r.URL.Path)) // "HTTP " + method + " " + path
		spanNameBuilder.WriteString("HTTP ")
		spanNameBuilder.WriteString(r.Method)
		spanNameBuilder.WriteByte(' ')
		spanNameBuilder.WriteString(r.URL.Path)
		spanName := spanNameBuilder.String()
		cacher.PutBuilder(spanNameBuilder)
		ctx, span := tracer.Start(ctx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.URLPath(r.URL.Path),
				semconv.URLScheme(r.URL.Scheme),
				semconv.ServerAddress(r.Host),
				semconv.UserAgentOriginal(r.UserAgent()),
				semconv.ClientAddress(r.RemoteAddr),
				semconv.HTTPRequestBodySize(int(r.ContentLength)),
			),
		)
		
		// Record trace coverage
		updateTraceCoverage(configID, traceSampled)
		
		defer func() {
			span.End()
			duration := time.Since(spanStartTime).Seconds()
			metric.TraceSpanDuration(spanName, "request", duration)
		}()

		if requestData := reqctx.GetRequestData(r.Context()); requestData != nil {
			span.SetAttributes(attribute.String("request.id", requestData.ID))
		}

		// Get a response writer wrapper from pool to capture status code
		wrappedWriter := getTracingWriter(w)

		// Update request context
		r = r.WithContext(ctx)

		// Inject trace context into request for downstream services
		propagator.Inject(ctx, propagation.HeaderCarrier(r.Header))

		// Inject W3C trace context headers into the response so callers can
		// correlate responses with distributed traces.
		propagator.Inject(ctx, propagation.HeaderCarrier(w.Header()))

		// Call the next handler
		next.ServeHTTP(wrappedWriter, r)

		// Record response status
		span.SetAttributes(
			semconv.HTTPResponseStatusCode(wrappedWriter.statusCode),
			semconv.HTTPResponseBodySize(int(wrappedWriter.written)),
		)

		// Set span status based on HTTP status code
		if wrappedWriter.statusCode >= 400 && wrappedWriter.statusCode < 500 {
			span.SetStatus(codes.Error, http.StatusText(wrappedWriter.statusCode))
		} else if wrappedWriter.statusCode >= 500 {
			span.SetStatus(codes.Error, http.StatusText(wrappedWriter.statusCode))
		} else {
			span.SetStatus(codes.Ok, "")
		}

		// Return writer to pool
		putTracingWriter(wrappedWriter)
	})
}

// tracingResponseWriter wraps http.ResponseWriter to capture status code and bytes written
type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int64
}

// WriteHeader captures the status code
func (w *tracingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write captures bytes written
func (w *tracingResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

// Flush implements http.Flusher to support streaming responses and chunk caching
func (w *tracingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker to support WebSocket connections
func (w *tracingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, ErrHijackerNotSupported
}

// Unwrap returns the original ResponseWriter
func (w *tracingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// traceCoverageKey uses a struct instead of string concatenation to avoid
// per-request allocation. The map has bounded cardinality (2 entries per origin).
type traceCoverageKey struct {
	origin  string
	sampled bool
}

type traceCoverageStat struct {
	totalRequests  int64
	tracedRequests int64
}

var (
	traceCoverageStats = make(map[traceCoverageKey]*traceCoverageStat)
	traceCoverageMu    sync.RWMutex
)

func updateTraceCoverage(origin string, sampled bool) {
	key := traceCoverageKey{origin: origin, sampled: sampled}
	traceCoverageMu.Lock()
	defer traceCoverageMu.Unlock()

	stat, exists := traceCoverageStats[key]
	if !exists {
		stat = &traceCoverageStat{}
		traceCoverageStats[key] = stat
	}

	stat.totalRequests++
	if sampled {
		stat.tracedRequests++
	}

	// Update coverage metric periodically (every 10 requests)
	if stat.totalRequests%10 == 0 {
		coverage := float64(stat.tracedRequests) / float64(stat.totalRequests)
		sampledStr := "false"
		if sampled {
			sampledStr = "true"
		}
		metric.TraceCoverageSet(origin, sampledStr, coverage)
	}
}
