// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
package crypto

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "crypto"

// TracedCrypto wraps a Crypto with OpenTelemetry tracing
type TracedCrypto struct {
	Crypto
	tracer trace.Tracer
}

// NewTracedCrypto creates a new traced crypto wrapper
func NewTracedCrypto(crypto Crypto) Crypto {
	if crypto == nil {
		return nil
	}
	return &TracedCrypto{
		Crypto: crypto,
		tracer: otel.Tracer(tracerName),
	}
}

// Encrypt wraps the Encrypt operation with tracing
func (tc *TracedCrypto) Encrypt(data []byte) ([]byte, error) {
	_, span := tc.tracer.Start(context.Background(), "crypto.encrypt",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("crypto.operation", "encrypt"),
			attribute.Int("crypto.data_size", len(data)),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := tc.Crypto.Encrypt(data)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("crypto.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "crypto encrypt failed")
		return nil, err
	}

	span.SetAttributes(
		attribute.Int("crypto.result_size", len(result)),
	)
	span.SetStatus(codes.Ok, "")

	return result, nil
}

// Decrypt wraps the Decrypt operation with tracing
func (tc *TracedCrypto) Decrypt(data []byte) ([]byte, error) {
	_, span := tc.tracer.Start(context.Background(), "crypto.decrypt",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("crypto.operation", "decrypt"),
			attribute.Int("crypto.data_size", len(data)),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := tc.Crypto.Decrypt(data)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("crypto.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "crypto decrypt failed")
		return nil, err
	}

	span.SetAttributes(
		attribute.Int("crypto.result_size", len(result)),
	)
	span.SetStatus(codes.Ok, "")

	return result, nil
}

// Sign wraps the Sign operation with tracing
func (tc *TracedCrypto) Sign(data []byte) ([]byte, error) {
	_, span := tc.tracer.Start(context.Background(), "crypto.sign",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("crypto.operation", "sign"),
			attribute.Int("crypto.data_size", len(data)),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := tc.Crypto.Sign(data)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("crypto.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "crypto sign failed")
		return nil, err
	}

	span.SetAttributes(
		attribute.Int("crypto.result_size", len(result)),
	)
	span.SetStatus(codes.Ok, "")

	return result, nil
}

// Verify wraps the Verify operation with tracing
func (tc *TracedCrypto) Verify(data1 []byte, data2 []byte) (bool, error) {
	_, span := tc.tracer.Start(context.Background(), "crypto.verify",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("crypto.operation", "verify"),
			attribute.Int("crypto.data1_size", len(data1)),
			attribute.Int("crypto.data2_size", len(data2)),
		),
	)
	defer span.End()

	startTime := time.Now()
	result, err := tc.Crypto.Verify(data1, data2)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int64("crypto.duration_ms", duration.Milliseconds()),
		attribute.Bool("crypto.verification_result", result),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "crypto verify failed")
		return false, err
	}

	span.SetStatus(codes.Ok, "")
	return result, nil
}
