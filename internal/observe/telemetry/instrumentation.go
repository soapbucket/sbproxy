// Package telemetry collects and exports distributed tracing and observability data.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// StartSpan starts a new span with the given name and attributes
func StartSpan(ctx context.Context, spanName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	tracer := otel.Tracer("github.com/soapbucket/sbproxy")
	ctx, span := tracer.Start(ctx, spanName)
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
	return ctx, span
}

// RecordError records an error on the span
func RecordError(span trace.Span, err error, description string) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, description)
	}
}

// SetSpanAttributes sets attributes on the span
func SetSpanAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	span.SetAttributes(attrs...)
}

// SpanFromContext returns the span from the context
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// Common attribute keys
var (
	// Cache attributes
	AttrCacheKey = attribute.Key("cache.key")
	// AttrCacheHit is a variable for attr cache hit.
	AttrCacheHit = attribute.Key("cache.hit")
	// AttrCacheTTL is a variable for attr cache ttl.
	AttrCacheTTL = attribute.Key("cache.ttl")
	// AttrCacheSize is a variable for attr cache size.
	AttrCacheSize = attribute.Key("cache.size")
	// AttrCacheType is a variable for attr cache type.
	AttrCacheType = attribute.Key("cache.type")

	// Transform attributes
	AttrTransformType = attribute.Key("transform.type")
	// AttrTransformInputSize is a variable for attr transform input size.
	AttrTransformInputSize = attribute.Key("transform.input_size")
	// AttrTransformOutputSize is a variable for attr transform output size.
	AttrTransformOutputSize = attribute.Key("transform.output_size")
	// AttrTransformContentType is a variable for attr transform content type.
	AttrTransformContentType = attribute.Key("transform.content_type")

	// Origin attributes
	AttrOriginURL = attribute.Key("origin.url")
	// AttrOriginHost is a variable for attr origin host.
	AttrOriginHost = attribute.Key("origin.host")
	// AttrOriginStatus is a variable for attr origin status.
	AttrOriginStatus = attribute.Key("origin.status_code")
	// AttrOriginDuration is a variable for attr origin duration.
	AttrOriginDuration = attribute.Key("origin.duration_ms")

	// Proxy attributes
	AttrProxyRecursion = attribute.Key("proxy.recursion_depth")
	// AttrProxyBackend is a variable for attr proxy backend.
	AttrProxyBackend = attribute.Key("proxy.backend")

	// Middleware attributes
	AttrMiddlewareName = attribute.Key("middleware.name")
	// AttrUserAgentType is a variable for attr user agent type.
	AttrUserAgentType = attribute.Key("user_agent.type")
	// AttrFingerprint is a variable for attr fingerprint.
	AttrFingerprint = attribute.Key("fingerprint.ja3")
)

// Helper functions for common operations

// TraceCache wraps cache operations with tracing
func TraceCache(ctx context.Context, operation string, cacheType string, key string, fn func(context.Context) error) error {
	ctx, span := StartSpan(ctx, "cache."+operation,
		AttrCacheType.String(cacheType),
		AttrCacheKey.String(key),
	)
	defer span.End()

	err := fn(ctx)
	if err != nil {
		RecordError(span, err, "cache operation failed")
	}

	return err
}

// TraceTransform wraps transform operations with tracing
func TraceTransform(ctx context.Context, transformType string, contentType string, fn func(context.Context) error) error {
	ctx, span := StartSpan(ctx, "transform."+transformType,
		AttrTransformType.String(transformType),
		AttrTransformContentType.String(contentType),
	)
	defer span.End()

	err := fn(ctx)
	if err != nil {
		RecordError(span, err, "transform operation failed")
	}

	return err
}

// TraceOriginRequest wraps origin requests with tracing
func TraceOriginRequest(ctx context.Context, url string, fn func(context.Context) error) error {
	ctx, span := StartSpan(ctx, "origin.request",
		AttrOriginURL.String(url),
	)
	defer span.End()

	err := fn(ctx)
	if err != nil {
		RecordError(span, err, "origin request failed")
	}

	return err
}
