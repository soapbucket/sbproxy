// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// --- zap tracing helpers ---

// ZapTracingFields extracts OpenTelemetry trace/span IDs as zap fields.
func ZapTracingFields(ctx context.Context) []zap.Field {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return nil
	}
	return []zap.Field{
		zap.String(FieldTraceID, spanCtx.TraceID().String()),
		zap.String(FieldSpanID, spanCtx.SpanID().String()),
	}
}

// --- slog tracing helpers (backward compat) ---

// ContextWithTracing extracts tracing information from the context and adds it to slog attributes.
func ContextWithTracing(ctx context.Context) []slog.Attr {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return nil
	}
	return []slog.Attr{
		slog.Group("tracing",
			slog.String("trace_id", spanCtx.TraceID().String()),
			slog.String("span_id", spanCtx.SpanID().String()),
		),
	}
}

// LoggerWithTracing creates a logger with tracing information from the context.
func LoggerWithTracing(ctx context.Context, logger *slog.Logger) *slog.Logger {
	attrs := ContextWithTracing(ctx)
	if len(attrs) == 0 {
		return logger
	}
	args := make([]any, len(attrs))
	for i, attr := range attrs {
		args[i] = attr
	}
	return logger.With(args...)
}

// AddTracingToAttrs adds tracing information to existing slog attributes.
func AddTracingToAttrs(ctx context.Context, attrs []any) []any {
	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.IsValid() {
		attrs = append(attrs,
			slog.Group("tracing",
				slog.String("trace_id", spanCtx.TraceID().String()),
				slog.String("span_id", spanCtx.SpanID().String()),
			),
		)
	}
	return attrs
}

// StandardRequestFields returns standard request field names for consistent logging.
func StandardRequestFields() map[string]string {
	return map[string]string{
		"id":          "request_id",
		"method":      "method",
		"path":        "path",
		"host":        "host",
		"remote_addr": "remote_addr",
		"user_agent":  "user_agent",
		"status_code": "status_code",
		"duration_ms": "duration_ms",
		"bytes":       "bytes",
	}
}

// StandardUserFields returns standard user field names.
func StandardUserFields() map[string]string {
	return map[string]string{
		"id":    "user_id",
		"email": "email",
		"roles": "roles",
	}
}

// StandardOriginFields returns standard origin field names.
func StandardOriginFields() map[string]string {
	return map[string]string{
		"id":       "origin_id",
		"hostname": "hostname",
		"type":     "type",
	}
}

// StandardErrorFields returns standard error field names.
func StandardErrorFields() map[string]string {
	return map[string]string{
		"type":    "error_type",
		"message": "error_message",
		"code":    "error_code",
		"stack":   "stack_trace",
	}
}
