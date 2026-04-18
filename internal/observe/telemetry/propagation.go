// Package telemetry collects and exports distributed tracing and observability data.
package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// TraceContext holds parsed trace context from incoming requests.
type TraceContext struct {
	TraceID    string
	SpanID     string
	ParentID   string
	Sampled    bool
	TraceState string // W3C tracestate header
}

// --- W3C Trace Context (https://www.w3.org/TR/trace-context/) ---

// ExtractW3C extracts W3C traceparent and tracestate from request headers.
// traceparent format: {version}-{trace-id}-{parent-id}-{trace-flags}
// Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
func ExtractW3C(headers http.Header) *TraceContext {
	tp := headers.Get("Traceparent")
	if tp == "" {
		return nil
	}

	parts := strings.Split(tp, "-")
	if len(parts) != 4 {
		return nil
	}

	version := parts[0]
	traceID := parts[1]
	spanID := parts[2]
	flags := parts[3]

	// Version must be 2 hex chars
	if len(version) != 2 {
		return nil
	}
	// Trace ID must be 32 hex chars and not all zeros
	if len(traceID) != 32 || traceID == "00000000000000000000000000000000" {
		return nil
	}
	// Span ID must be 16 hex chars and not all zeros
	if len(spanID) != 16 || spanID == "0000000000000000" {
		return nil
	}
	// Flags must be 2 hex chars
	if len(flags) != 2 {
		return nil
	}

	// Validate hex encoding
	if !isHex(traceID) || !isHex(spanID) || !isHex(flags) || !isHex(version) {
		return nil
	}

	sampled := flags[1] == '1' // bit 0 of trace-flags

	ctx := &TraceContext{
		TraceID:    traceID,
		SpanID:     spanID,
		Sampled:    sampled,
		TraceState: headers.Get("Tracestate"),
	}

	return ctx
}

// InjectW3C adds W3C traceparent and tracestate to outgoing request headers.
func InjectW3C(ctx *TraceContext, headers http.Header) {
	if ctx == nil {
		return
	}

	flags := "00"
	if ctx.Sampled {
		flags = "01"
	}

	headers.Set("Traceparent", fmt.Sprintf("00-%s-%s-%s", ctx.TraceID, ctx.SpanID, flags))

	if ctx.TraceState != "" {
		headers.Set("Tracestate", ctx.TraceState)
	}
}

// --- B3 Propagation (https://github.com/openzipkin/b3-propagation) ---

// ExtractB3 extracts B3 single or multi headers from request.
// B3 single format: {trace-id}-{span-id}-{sampling}-{parent-span-id}
// B3 multi: X-B3-TraceId, X-B3-SpanId, X-B3-ParentSpanId, X-B3-Sampled
func ExtractB3(headers http.Header) *TraceContext {
	// Try single-header format first (b3: {traceid}-{spanid}-{sampling}-{parentspanid})
	b3Single := headers.Get("B3")
	if b3Single != "" {
		return parseB3Single(b3Single)
	}

	// Try multi-header format
	traceID := headers.Get("X-B3-TraceId")
	spanID := headers.Get("X-B3-SpanId")
	if traceID == "" || spanID == "" {
		return nil
	}

	// Pad 64-bit trace IDs to 128-bit
	if len(traceID) == 16 {
		traceID = "0000000000000000" + traceID
	}

	if len(traceID) != 32 || !isHex(traceID) {
		return nil
	}
	if len(spanID) != 16 || !isHex(spanID) {
		return nil
	}

	ctx := &TraceContext{
		TraceID:  traceID,
		SpanID:   spanID,
		ParentID: headers.Get("X-B3-ParentSpanId"),
		Sampled:  headers.Get("X-B3-Sampled") == "1",
	}

	return ctx
}

// InjectB3 adds B3 multi-headers to outgoing request.
func InjectB3(ctx *TraceContext, headers http.Header) {
	if ctx == nil {
		return
	}

	headers.Set("X-B3-TraceId", ctx.TraceID)
	headers.Set("X-B3-SpanId", ctx.SpanID)

	if ctx.ParentID != "" {
		headers.Set("X-B3-ParentSpanId", ctx.ParentID)
	}

	sampled := "0"
	if ctx.Sampled {
		sampled = "1"
	}
	headers.Set("X-B3-Sampled", sampled)
}

// --- Generic Extraction ---

// Extract tries W3C first, then B3. Returns nil if neither is present.
func Extract(headers http.Header) *TraceContext {
	if ctx := ExtractW3C(headers); ctx != nil {
		return ctx
	}
	return ExtractB3(headers)
}

// --- ID Generation ---

// GenerateTraceID generates a random 32-char hex trace ID (128-bit).
func GenerateTraceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback should never happen in practice, but avoid panic.
		return "00000000000000000000000000000001"
	}
	return hex.EncodeToString(b)
}

// GenerateSpanID generates a random 16-char hex span ID (64-bit).
func GenerateSpanID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000001"
	}
	return hex.EncodeToString(b)
}

// --- Internal helpers ---

// parseB3Single parses the B3 single-header format.
// Format: {trace-id}-{span-id}-{sampling}-{parent-span-id}
// Minimal: {trace-id}-{span-id}
func parseB3Single(value string) *TraceContext {
	// Handle deny/accept shorthand
	if value == "0" || value == "d" {
		return &TraceContext{Sampled: false}
	}

	parts := strings.Split(value, "-")
	if len(parts) < 2 {
		return nil
	}

	traceID := parts[0]
	spanID := parts[1]

	// Pad 64-bit trace IDs to 128-bit
	if len(traceID) == 16 {
		traceID = "0000000000000000" + traceID
	}

	if len(traceID) != 32 || !isHex(traceID) {
		return nil
	}
	if len(spanID) != 16 || !isHex(spanID) {
		return nil
	}

	ctx := &TraceContext{
		TraceID: traceID,
		SpanID:  spanID,
		Sampled: true, // default to sampled if not specified
	}

	if len(parts) >= 3 {
		switch parts[2] {
		case "0":
			ctx.Sampled = false
		case "1", "d":
			ctx.Sampled = true
		}
	}

	if len(parts) >= 4 {
		parentID := parts[3]
		if len(parentID) == 16 && isHex(parentID) {
			ctx.ParentID = parentID
		}
	}

	return ctx
}

// isHex returns true if s contains only valid hexadecimal characters.
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
