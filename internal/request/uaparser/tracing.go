// Package uaparser parses User-Agent strings to extract browser, OS, and device information.
package uaparser

import (
	"context"
	"time"

	"github.com/ua-parser/uap-go/uaparser"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName = "github.com/soapbucket/sbproxy/internal/request/uaparser"
)

// TracedManager wraps a Manager with OpenTelemetry tracing
type TracedManager struct {
	Manager
	tracer trace.Tracer
}

// NewTracedManager creates a new traced manager
func NewTracedManager(manager Manager) Manager {
	if manager == nil {
		return nil
	}
	return &TracedManager{
		Manager: manager,
		tracer:  otel.Tracer(tracerName),
	}
}

// Parse wraps the Parse operation with tracing
func (tm *TracedManager) Parse(userAgent string) (*Result, error) {
	ctx := context.Background()
	ctx, span := tm.tracer.Start(ctx, "uaparser.parse",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("uaparser.operation", "parse"),
			attribute.String("uaparser.user_agent", userAgent),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := tm.Manager.Parse(userAgent)
	duration := time.Since(startTime)

	// Record metrics
	span.SetAttributes(
		attribute.Int64("uaparser.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "uaparser parse failed")
		return nil, err
	}

	// Add result attributes for tracing
	if result != nil {
		attrs := []attribute.KeyValue{
			attribute.String("uaparser.browser_family", getStringValue(result.UserAgent, "Family")),
			attribute.String("uaparser.browser_major", getStringValue(result.UserAgent, "Major")),
			attribute.String("uaparser.browser_minor", getStringValue(result.UserAgent, "Minor")),
			attribute.String("uaparser.os_family", getStringValue(result.OS, "Family")),
			attribute.String("uaparser.os_major", getStringValue(result.OS, "Major")),
			attribute.String("uaparser.os_minor", getStringValue(result.OS, "Minor")),
			attribute.String("uaparser.device_family", getStringValue(result.Device, "Family")),
			attribute.String("uaparser.device_brand", getStringValue(result.Device, "Brand")),
			attribute.String("uaparser.device_model", getStringValue(result.Device, "Model")),
		}
		span.SetAttributes(attrs...)
	}

	span.SetStatus(codes.Ok, "")
	return result, nil
}

// Close wraps the Close operation with tracing
func (tm *TracedManager) Close() error {
	ctx := context.Background()
	_, span := tm.tracer.Start(ctx, "uaparser.close",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("uaparser.operation", "close"),
		),
	)
	defer span.End()

	err := tm.Manager.Close()

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "uaparser close failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// Helper function to safely get string values from potentially nil structs
func getStringValue(ptr interface{}, field string) string {
	if ptr == nil {
		return "unknown"
	}

	// Use type assertion to safely extract values
	switch v := ptr.(type) {
	case *uaparser.UserAgent:
		switch field {
		case "Family":
			return v.Family
		case "Major":
			return v.Major
		case "Minor":
			return v.Minor
		case "Patch":
			return v.Patch
		}
	case *uaparser.Os:
		switch field {
		case "Family":
			return v.Family
		case "Major":
			return v.Major
		case "Minor":
			return v.Minor
		case "Patch":
			return v.Patch
		}
	case *uaparser.Device:
		switch field {
		case "Family":
			return v.Family
		case "Brand":
			return v.Brand
		case "Model":
			return v.Model
		}
	}

	return "unknown"
}
