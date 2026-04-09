// Package geoip provides GeoIP database integration for geographic request metadata.
package geoip

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
	tracerName = "github.com/soapbucket/sbproxy/internal/request/geoip"
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
	_, span := tm.tracer.Start(ctx, "geoip.lookup",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("geoip.operation", "lookup"),
			attribute.String("geoip.ip", ip.String()),
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
	span.SetAttributes(attribute.String("geoip.ip_version", ipVersion))

	startTime := time.Now()
	result, err := tm.Manager.Lookup(ip)
	duration := time.Since(startTime)

	// Record metrics
	span.SetAttributes(
		attribute.Int64("geoip.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "geoip lookup failed")
		return nil, err
	}

	// Add result attributes for tracing
	if result != nil {
		span.SetAttributes(
			attribute.String("geoip.country", result.Country),
			attribute.String("geoip.country_code", result.CountryCode),
			attribute.String("geoip.continent", result.Continent),
			attribute.String("geoip.continent_code", result.ContinentCode),
			attribute.String("geoip.asn", result.ASN),
			attribute.String("geoip.as_name", result.ASName),
			attribute.String("geoip.as_domain", result.ASDomain),
		)
	}

	span.SetStatus(codes.Ok, "")
	return result, nil
}

// Close wraps the Close operation with tracing
func (tm *TracedManager) Close() error {
	ctx := context.Background()
	_, span := tm.tracer.Start(ctx, "geoip.close",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("geoip.operation", "close"),
		),
	)
	defer span.End()

	err := tm.Manager.Close()

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "geoip close failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}
