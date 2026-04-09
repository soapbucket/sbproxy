// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"bytes"
	"context"
	"io"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TracedManager wraps a Cacher with OpenTelemetry tracing
type TracedManager struct {
	Cacher
	tracer trace.Tracer
}

// NewTracedManager creates a new traced cache manager
func NewTracedManager(cacher Cacher) Cacher {
	if cacher == nil {
		return nil
	}
	return &TracedManager{
		Cacher: cacher,
		tracer: otel.Tracer(tracerName),
	}
}

// Get wraps the Get operation with tracing
func (tm *TracedManager) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	ctx, span := tm.tracer.Start(ctx, "cache.get",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.c_type", cType),
			attribute.String("cache.key", key),
			attribute.String("cache.operation", "get"),
		),
	)
	defer span.End()

	startTime := time.Now()
	reader, err := tm.Cacher.Get(ctx, cType, key)
	duration := time.Since(startTime)

	// Record metrics
	span.SetAttributes(
		attribute.Int64("cache.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.SetAttributes(attribute.Bool("cache.hit", false))
		span.RecordError(err)
		span.SetStatus(codes.Error, "cache get failed")
		return nil, err
	}

	// Read the data to get size for metrics
	data, readErr := io.ReadAll(reader)
	if readErr != nil {
		span.RecordError(readErr)
		span.SetStatus(codes.Error, "failed to read cache value")
		return nil, readErr
	}

	span.SetAttributes(
		attribute.Bool("cache.hit", len(data) > 0),
		attribute.Int("cache.value_size", len(data)),
	)
	span.SetStatus(codes.Ok, "")

	return bytes.NewReader(data), nil
}

// Put wraps the Put operation with tracing
func (tm *TracedManager) Put(ctx context.Context, cType string, key string, value io.Reader) error {
	ctx, span := tm.tracer.Start(ctx, "cache.put",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.c_type", cType),
			attribute.String("cache.key", key),
			attribute.String("cache.operation", "put"),
		),
	)
	defer span.End()

	// Read the data to get size for metrics
	data, readErr := io.ReadAll(value)
	if readErr != nil {
		span.RecordError(readErr)
		span.SetStatus(codes.Error, "failed to read input value")
		return readErr
	}

	span.SetAttributes(attribute.Int("cache.value_size", len(data)))

	startTime := time.Now()
	err := tm.Cacher.Put(ctx, cType, key, bytes.NewReader(data))
	duration := time.Since(startTime)

	span.SetAttributes(attribute.Int64("cache.duration_ms", duration.Milliseconds()))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cache put failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// PutWithExpires wraps the PutWithExpires operation with tracing
func (tm *TracedManager) PutWithExpires(ctx context.Context, cType string, key string, value io.Reader, ttl time.Duration) error {
	ctx, span := tm.tracer.Start(ctx, "cache.put_with_expires",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.c_type", cType),
			attribute.String("cache.key", key),
			attribute.String("cache.operation", "put_with_expires"),
			attribute.Int64("cache.ttl_seconds", int64(ttl.Seconds())),
		),
	)
	defer span.End()

	// Read the data to get size for metrics
	data, readErr := io.ReadAll(value)
	if readErr != nil {
		span.RecordError(readErr)
		span.SetStatus(codes.Error, "failed to read input value")
		return readErr
	}

	span.SetAttributes(attribute.Int("cache.value_size", len(data)))

	startTime := time.Now()
	err := tm.Cacher.PutWithExpires(ctx, cType, key, bytes.NewReader(data), ttl)
	duration := time.Since(startTime)

	span.SetAttributes(attribute.Int64("cache.duration_ms", duration.Milliseconds()))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cache put with expires failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// Delete wraps the Delete operation with tracing
func (tm *TracedManager) Delete(ctx context.Context, cType string, key string) error {
	ctx, span := tm.tracer.Start(ctx, "cache.delete",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.c_type", cType),
			attribute.String("cache.key", key),
			attribute.String("cache.operation", "delete"),
		),
	)
	defer span.End()

	startTime := time.Now()
	err := tm.Cacher.Delete(ctx, cType, key)
	duration := time.Since(startTime)

	span.SetAttributes(attribute.Int64("cache.duration_ms", duration.Milliseconds()))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cache delete failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// DeleteByPattern wraps the DeleteByPattern operation with tracing
func (tm *TracedManager) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	ctx, span := tm.tracer.Start(ctx, "cache.delete_by_pattern",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.c_type", cType),
			attribute.String("cache.pattern", pattern),
			attribute.String("cache.operation", "delete_by_pattern"),
		),
	)
	defer span.End()

	startTime := time.Now()
	err := tm.Cacher.DeleteByPattern(ctx, cType, pattern)
	duration := time.Since(startTime)

	span.SetAttributes(attribute.Int64("cache.duration_ms", duration.Milliseconds()))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cache delete by pattern failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// Increment wraps the Increment operation with tracing
func (tm *TracedManager) Increment(ctx context.Context, cType string, key string, value int64) (int64, error) {
	ctx, span := tm.tracer.Start(ctx, "cache.increment",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.c_type", cType),
			attribute.String("cache.key", key),
			attribute.String("cache.operation", "increment"),
			attribute.Int64("cache.increment_value", value),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := tm.Cacher.Increment(ctx, cType, key, value)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("cache.duration_ms", duration.Milliseconds()),
		attribute.Int64("cache.result_value", result),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cache increment failed")
		return 0, err
	}

	span.SetStatus(codes.Ok, "")
	return result, nil
}

// IncrementWithExpires wraps the IncrementWithExpires operation with tracing
func (tm *TracedManager) IncrementWithExpires(ctx context.Context, cType string, key string, value int64, ttl time.Duration) (int64, error) {
	ctx, span := tm.tracer.Start(ctx, "cache.increment_with_expires",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.c_type", cType),
			attribute.String("cache.key", key),
			attribute.String("cache.operation", "increment_with_expires"),
			attribute.Int64("cache.increment_value", value),
			attribute.Int64("cache.ttl_seconds", int64(ttl.Seconds())),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := tm.Cacher.IncrementWithExpires(ctx, cType, key, value, ttl)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("cache.duration_ms", duration.Milliseconds()),
		attribute.Int64("cache.result_value", result),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cache increment with expires failed")
		return 0, err
	}

	span.SetStatus(codes.Ok, "")
	return result, nil
}

// Close wraps the Close operation with tracing
func (tm *TracedManager) Close() error {
	_, span := tm.tracer.Start(context.Background(), "cache.close",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.operation", "close"),
		),
	)
	defer span.End()

	err := tm.Cacher.Close()

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cache close failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}
