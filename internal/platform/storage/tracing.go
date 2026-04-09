// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "storage"

// TracedStorage wraps a Storage with OpenTelemetry tracing
type TracedStorage struct {
	Storage
	tracer trace.Tracer
}

// NewTracedStorage creates a new traced storage wrapper
func NewTracedStorage(storage Storage) Storage {
	if storage == nil {
		return nil
	}
	return &TracedStorage{
		Storage: storage,
		tracer:  otel.Tracer(tracerName),
	}
}

// Get wraps the Get operation with tracing
func (ts *TracedStorage) Get(ctx context.Context, key string) ([]byte, error) {
	ctx, span := ts.tracer.Start(ctx, "storage.get",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("storage.key", key),
			attribute.String("storage.operation", "get"),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := ts.Storage.Get(ctx, key)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("storage.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "storage get failed")
		return nil, err
	}

	span.SetAttributes(
		attribute.Int("storage.value_size", len(result)),
	)
	span.SetStatus(codes.Ok, "")

	return result, nil
}

// GetByID wraps the GetByID operation with tracing
func (ts *TracedStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	ctx, span := ts.tracer.Start(ctx, "storage.get_by_id",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("storage.id", id),
			attribute.String("storage.operation", "get_by_id"),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := ts.Storage.GetByID(ctx, id)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("storage.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "storage get by id failed")
		return nil, err
	}

	span.SetAttributes(
		attribute.Int("storage.value_size", len(result)),
	)
	span.SetStatus(codes.Ok, "")

	return result, nil
}

// Put wraps the Put operation with tracing
func (ts *TracedStorage) Put(ctx context.Context, key string, data []byte) error {
	ctx, span := ts.tracer.Start(ctx, "storage.put",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("storage.key", key),
			attribute.String("storage.operation", "put"),
			attribute.Int("storage.value_size", len(data)),
		),
	)
	defer span.End()

	startTime := time.Now()
	err := ts.Storage.Put(ctx, key, data)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("storage.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "storage put failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// Delete wraps the Delete operation with tracing
func (ts *TracedStorage) Delete(ctx context.Context, key string) error {
	ctx, span := ts.tracer.Start(ctx, "storage.delete",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("storage.key", key),
			attribute.String("storage.operation", "delete"),
		),
	)
	defer span.End()

	startTime := time.Now()
	err := ts.Storage.Delete(ctx, key)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("storage.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "storage delete failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// DeleteByPrefix wraps the DeleteByPrefix operation with tracing
func (ts *TracedStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	ctx, span := ts.tracer.Start(ctx, "storage.delete_by_prefix",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("storage.prefix", prefix),
			attribute.String("storage.operation", "delete_by_prefix"),
		),
	)
	defer span.End()

	startTime := time.Now()
	err := ts.Storage.DeleteByPrefix(ctx, prefix)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("storage.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "storage delete by prefix failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// ListKeys wraps the ListKeys operation with tracing
func (ts *TracedStorage) ListKeys(ctx context.Context) ([]string, error) {
	ctx, span := ts.tracer.Start(ctx, "storage.list_keys",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("storage.operation", "list_keys"),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := ts.Storage.ListKeys(ctx)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("storage.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "storage list keys failed")
		return nil, err
	}

	span.SetAttributes(attribute.Int("storage.key_count", len(result)))
	span.SetStatus(codes.Ok, "")
	return result, nil
}

// ListKeysByWorkspace wraps the ListKeysByWorkspace operation with tracing
func (ts *TracedStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	ctx, span := ts.tracer.Start(ctx, "storage.list_keys_by_workspace",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("storage.operation", "list_keys_by_workspace"),
			attribute.String("storage.workspace_id", workspaceID),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := ts.Storage.ListKeysByWorkspace(ctx, workspaceID)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("storage.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "storage list keys by workspace failed")
		return nil, err
	}

	span.SetAttributes(attribute.Int("storage.key_count", len(result)))
	span.SetStatus(codes.Ok, "")
	return result, nil
}

// Close wraps the Close operation with tracing
func (ts *TracedStorage) Close() error {
	_, span := ts.tracer.Start(context.Background(), "storage.close",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("storage.operation", "close"),
		),
	)
	defer span.End()

	err := ts.Storage.Close()

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "storage close failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}
