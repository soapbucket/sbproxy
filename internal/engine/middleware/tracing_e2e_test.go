package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// setupTestTracer installs a minimal OTel tracer and W3C propagator for testing.
// Returns a cleanup function that should be deferred.
func setupTestTracer(t *testing.T) func() {
	t.Helper()

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return func() {
		_ = tp.Shutdown(nil)
	}
}

// TestTraceContext_E2E_ResponseIncludesTraceparent verifies that the tracing
// middleware injects a traceparent header into the response so callers can
// correlate responses with distributed traces.
func TestTraceContext_E2E_ResponseIncludesTraceparent(t *testing.T) {
	cleanup := setupTestTracer(t)
	defer cleanup()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := TracingMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	traceparent := rr.Header().Get("Traceparent")
	if traceparent == "" {
		t.Fatal("expected Traceparent header in response, but it was empty")
	}

	// W3C traceparent format: version-trace_id-parent_id-trace_flags
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		t.Errorf("expected 4 parts in traceparent, got %d: %q", len(parts), traceparent)
	}
	if parts[0] != "00" {
		t.Errorf("expected traceparent version '00', got %q", parts[0])
	}
}

// TestTraceContext_E2E_PropagatesIncomingTraceID verifies that when an incoming
// request has a traceparent header, the trace ID is preserved and propagated to
// the upstream (via the request context).
func TestTraceContext_E2E_PropagatesIncomingTraceID(t *testing.T) {
	cleanup := setupTestTracer(t)
	defer cleanup()

	// A valid traceparent with a known trace ID.
	incomingTraceID := "0af7651916cd43dd8448eb211c80319c"
	incomingTraceparent := "00-" + incomingTraceID + "-b7ad6b7169203331-01"

	var upstreamTraceparent string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The tracing middleware injects trace context into the request headers.
		upstreamTraceparent = r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusOK)
	})

	handler := TracingMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/data", nil)
	req.Header.Set("Traceparent", incomingTraceparent)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The upstream should receive a traceparent with the same trace ID.
	if upstreamTraceparent == "" {
		t.Fatal("expected upstream to receive Traceparent header")
	}

	upstreamParts := strings.Split(upstreamTraceparent, "-")
	if len(upstreamParts) != 4 {
		t.Fatalf("invalid upstream traceparent format: %q", upstreamTraceparent)
	}

	if upstreamParts[1] != incomingTraceID {
		t.Errorf("upstream trace ID = %q, want %q (incoming trace ID should be preserved)", upstreamParts[1], incomingTraceID)
	}

	// Response should also include traceparent with the same trace ID.
	respTraceparent := rr.Header().Get("Traceparent")
	if respTraceparent == "" {
		t.Fatal("expected Traceparent in response")
	}
	respParts := strings.Split(respTraceparent, "-")
	if len(respParts) != 4 || respParts[1] != incomingTraceID {
		t.Errorf("response trace ID = %q, want %q", respParts[1], incomingTraceID)
	}
}

// TestTraceContext_UpstreamGetsNewSpanID verifies that the tracing middleware
// creates a new child span for the upstream request: the trace ID must be
// preserved (same distributed trace) but the span ID must differ (new span).
func TestTraceContext_UpstreamGetsNewSpanID(t *testing.T) {
	cleanup := setupTestTracer(t)
	defer cleanup()

	incomingTraceID := "0af7651916cd43dd8448eb211c80319c"
	incomingSpanID := "b7ad6b7169203331"
	incomingTraceparent := "00-" + incomingTraceID + "-" + incomingSpanID + "-01"

	var upstreamTraceparent string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamTraceparent = r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusOK)
	})

	handler := TracingMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/span-check", nil)
	req.Header.Set("Traceparent", incomingTraceparent)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if upstreamTraceparent == "" {
		t.Fatal("expected upstream to receive Traceparent header")
	}

	parts := strings.Split(upstreamTraceparent, "-")
	if len(parts) != 4 {
		t.Fatalf("invalid upstream traceparent format: %q", upstreamTraceparent)
	}

	// Trace ID must be preserved (same distributed trace).
	if parts[1] != incomingTraceID {
		t.Errorf("upstream trace ID = %q, want %q", parts[1], incomingTraceID)
	}

	// Span ID must differ (the middleware created a new child span).
	if parts[2] == incomingSpanID {
		t.Errorf("upstream span ID should differ from incoming span ID %q, but they are the same. "+
			"The middleware should create a new child span.", incomingSpanID)
	}

	t.Logf("incoming spanID=%s, upstream spanID=%s (correctly different)", incomingSpanID, parts[2])
}
