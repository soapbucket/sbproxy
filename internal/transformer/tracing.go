// Package transformer applies content transformations to HTTP request and response bodies.
package transformer

import (
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName = "github.com/soapbucket/sbproxy/internal/transformer"
)

// TracedTransform wraps a Transformer with OpenTelemetry tracing
type TracedTransform struct {
	Transformer
	tracer trace.Tracer
	name   string
}

// NewTracedTransform creates a new traced transformer
func NewTracedTransform(t Transformer, name string) Transformer {
	if t == nil {
		return Noop
	}
	return &TracedTransform{
		Transformer: t,
		tracer:      otel.Tracer(tracerName),
		name:        name,
	}
}

// Modify wraps the Modify operation with tracing
func (tt *TracedTransform) Modify(resp *http.Response) error {
	ctx := resp.Request.Context()
	ctx, span := tt.tracer.Start(ctx, "transformer."+tt.name,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("transformer.type", tt.name),
			attribute.String("transformer.content_type", resp.Header.Get("Content-Type")),
			attribute.Int("transformer.status_code", resp.StatusCode),
			attribute.Int64("transformer.content_length", resp.ContentLength),
		),
	)
	defer span.End()

	// Update response context
	resp.Request = resp.Request.WithContext(ctx)

	err := tt.Transformer.Modify(resp)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "transform failed")
		return err
	}

	// Record output size if available
	if resp.ContentLength >= 0 {
		span.SetAttributes(attribute.Int64("transformer.output_size", resp.ContentLength))
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// TracedWrap wraps multiple Transformers with tracing
func TracedWrap(transforms ...Transformer) Transformer {
	if len(transforms) == 0 {
		return Noop
	}

	tracedTransforms := make([]Transformer, len(transforms))
	for i, t := range transforms {
		tracedTransforms[i] = NewTracedTransform(t, "transform")
	}

	return Wrap(tracedTransforms...)
}
