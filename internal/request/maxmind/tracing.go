// Package maxmind integrates MaxMind GeoIP databases for geographic request metadata.
package maxmind

import (
	"context"
	"net"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName = "github.com/soapbucket/sbproxy/internal/request/maxmind"
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

// Lookup wraps the Lookup operation with tracing
func (tm *TracedManager) Lookup(ip net.IP) (*Result, error) {
	ctx := context.Background()
	ctx, span := tm.tracer.Start(ctx, "maxmind.lookup",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("maxmind.operation", "lookup"),
			attribute.String("maxmind.ip", ip.String()),
		),
	)
	defer span.End()

	// Determine IP version for tracing
	ipVersion := "unknown"
	if ip != nil {
		if ip.To4() != nil {
			ipVersion = "ipv4"
		} else if ip.To16() != nil {
			ipVersion = "ipv6"
		}
	}
	span.SetAttributes(attribute.String("maxmind.ip_version", ipVersion))

	startTime := time.Now()
	result, err := tm.Manager.Lookup(ip)
	duration := time.Since(startTime)

	// Record metrics
	span.SetAttributes(
		attribute.Int64("maxmind.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "maxmind lookup failed")
		return nil, err
	}

	// Add result attributes for tracing
	if result != nil {
		span.SetAttributes(
			attribute.String("maxmind.country", result.Country),
			attribute.String("maxmind.country_code", result.CountryCode),
			attribute.String("maxmind.continent", result.Continent),
			attribute.String("maxmind.continent_code", result.ContinentCode),
			attribute.String("maxmind.asn", result.ASN),
			attribute.String("maxmind.as_name", result.ASName),
			attribute.String("maxmind.as_domain", result.ASDomain),
		)
	}

	span.SetStatus(codes.Ok, "")
	return result, nil
}

// Close wraps the Close operation with tracing
func (tm *TracedManager) Close() error {
	ctx := context.Background()
	_, span := tm.tracer.Start(ctx, "maxmind.close",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("maxmind.operation", "close"),
		),
	)
	defer span.End()

	err := tm.Manager.Close()

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "maxmind close failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}
