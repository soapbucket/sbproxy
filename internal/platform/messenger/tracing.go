// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "messenger"

// TracedMessenger wraps a Messenger with OpenTelemetry tracing
type TracedMessenger struct {
	Messenger
	tracer trace.Tracer
}

// NewTracedMessenger creates a new traced messenger wrapper
func NewTracedMessenger(messenger Messenger) Messenger {
	if messenger == nil {
		return nil
	}
	return &TracedMessenger{
		Messenger: messenger,
		tracer:    otel.Tracer(tracerName),
	}
}

// Send wraps the Send operation with tracing
func (tm *TracedMessenger) Send(ctx context.Context, channel string, message *Message) error {
	ctx, span := tm.tracer.Start(ctx, "messenger.send",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("messenger.channel", channel),
			attribute.String("messenger.operation", "send"),
			attribute.Int("messenger.message_size", len(message.Body)),
		),
	)
	defer span.End()

	startTime := time.Now()
	err := tm.Messenger.Send(ctx, channel, message)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("messenger.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "messenger send failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// Subscribe wraps the Subscribe operation with tracing
func (tm *TracedMessenger) Subscribe(ctx context.Context, channel string, handler func(context.Context, *Message) error) error {
	ctx, span := tm.tracer.Start(ctx, "messenger.subscribe",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("messenger.channel", channel),
			attribute.String("messenger.operation", "subscribe"),
		),
	)
	defer span.End()

	// Wrap the handler to add tracing
	wrappedHandler := func(ctx context.Context, msg *Message) error {
		handlerCtx, handlerSpan := tm.tracer.Start(ctx, "messenger.message_handler",
			trace.WithSpanKind(trace.SpanKindConsumer),
			trace.WithAttributes(
				attribute.String("messenger.channel", channel),
				attribute.String("messenger.operation", "message_handler"),
				attribute.Int("messenger.message_size", len(msg.Body)),
			),
		)
		defer handlerSpan.End()

		handlerStartTime := time.Now()
		err := handler(handlerCtx, msg)
		handlerDuration := time.Since(handlerStartTime)

		handlerSpan.SetAttributes(
			attribute.Int64("messenger.duration_ms", handlerDuration.Milliseconds()),
		)

		if err != nil {
			handlerSpan.RecordError(err)
			handlerSpan.SetStatus(codes.Error, "message handler failed")
		} else {
			handlerSpan.SetStatus(codes.Ok, "")
		}

		return err
	}

	startTime := time.Now()
	err := tm.Messenger.Subscribe(ctx, channel, wrappedHandler)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("messenger.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "messenger subscribe failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// Unsubscribe wraps the Unsubscribe operation with tracing
func (tm *TracedMessenger) Unsubscribe(ctx context.Context, channel string) error {
	ctx, span := tm.tracer.Start(ctx, "messenger.unsubscribe",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("messenger.channel", channel),
			attribute.String("messenger.operation", "unsubscribe"),
		),
	)
	defer span.End()

	startTime := time.Now()
	err := tm.Messenger.Unsubscribe(ctx, channel)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("messenger.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "messenger unsubscribe failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// Close wraps the Close operation with tracing
func (tm *TracedMessenger) Close() error {
	_, span := tm.tracer.Start(context.Background(), "messenger.close",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("messenger.operation", "close"),
		),
	)
	defer span.End()

	err := tm.Messenger.Close()

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "messenger close failed")
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}
