// Package telemetry collects and exports distributed tracing and observability data.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.28.0"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/version"
)

// OTelConfig represents OpenTelemetry configuration
type OTelConfig struct {
	Enabled        bool     `json:"enabled"`
	OTLPEndpoint   string   `json:"otlp_endpoint"`
	OTLPProtocol   string   `json:"otlp_protocol"`
	OTLPInsecure   bool     `json:"otlp_insecure"`
	ServiceName    string   `json:"service_name"`
	ServiceVersion string   `json:"service_version"`
	Environment    string   `json:"environment"`
	SampleRate     float64  `json:"sample_rate"`
	Headers        []string `json:"headers,omitempty"`
}

var (
	tracerProvider *sdktrace.TracerProvider
)

// InitializeOTel initializes OpenTelemetry with the given configuration
func InitializeOTel(ctx context.Context, config OTelConfig) error {
	if !config.Enabled {
		slog.Info("OpenTelemetry is disabled",
			logging.FieldCaller, "telemetry:InitializeOTel")
		return nil
	}

	slog.Info("Initializing OpenTelemetry",
		logging.FieldCaller, "telemetry:InitializeOTel",
		"endpoint", config.OTLPEndpoint,
		"protocol", config.OTLPProtocol)

	// Set default values
	if config.ServiceName == "" {
		config.ServiceName = "soapbucket-proxy"
	}
	if config.ServiceVersion == "" {
		config.ServiceVersion = version.String()
	}
	if config.SampleRate == 0 {
		config.SampleRate = 1.0 // Default to 100% sampling
	}
	if config.Environment == "" {
		config.Environment = "development"
	}

	// Create resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(config.ServiceName),
			semconv.ServiceVersionKey.String(config.ServiceVersion),
			semconv.DeploymentEnvironmentNameKey.String(config.Environment),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create OTLP trace exporter
	traceExporter, err := createOTLPExporter(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create trace provider with batch span processor
	bsp := sdktrace.NewBatchSpanProcessor(traceExporter)
	tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(config.SampleRate)),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)

	// Set global trace provider
	otel.SetTracerProvider(tracerProvider)

	// Set global propagator to tracecontext (W3C Trace Context)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	slog.Info("OpenTelemetry initialized",
		logging.FieldCaller, "telemetry:InitializeOTel",
		"service", config.ServiceName,
		"version", config.ServiceVersion,
		"environment", config.Environment,
		"sample_rate", config.SampleRate)

	return nil
}

// parseHeaders parses header strings in "key=value" format into a map.
func parseHeaders(headers []string) map[string]string {
	result := make(map[string]string, len(headers))
	for _, h := range headers {
		parts := strings.SplitN(h, "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// createOTLPExporter creates an OTLP trace exporter using either gRPC or HTTP
// protocol depending on the OTLPProtocol config value. Supported values are
// "grpc" (default) and "http".
func createOTLPExporter(ctx context.Context, config OTelConfig) (*otlptrace.Exporter, error) {
	headers := parseHeaders(config.Headers)

	protocol := strings.ToLower(config.OTLPProtocol)
	if protocol == "http" || protocol == "http/protobuf" {
		return createHTTPExporter(ctx, config, headers)
	}
	return createGRPCExporter(ctx, config, headers)
}

// createGRPCExporter creates a gRPC-based OTLP exporter.
func createGRPCExporter(ctx context.Context, config OTelConfig, headers map[string]string) (*otlptrace.Exporter, error) {
	var opts []otlptracegrpc.Option

	if config.OTLPEndpoint != "" {
		opts = append(opts, otlptracegrpc.WithEndpoint(config.OTLPEndpoint))
	}
	if config.OTLPInsecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	if len(headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(headers))
	}
	opts = append(opts, otlptracegrpc.WithTimeout(10*time.Second))

	return otlptracegrpc.New(ctx, opts...)
}

// createHTTPExporter creates an HTTP/protobuf-based OTLP exporter.
func createHTTPExporter(ctx context.Context, config OTelConfig, headers map[string]string) (*otlptrace.Exporter, error) {
	var opts []otlptracehttp.Option

	if config.OTLPEndpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpoint(config.OTLPEndpoint))
	}
	if config.OTLPInsecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}
	opts = append(opts, otlptracehttp.WithTimeout(10*time.Second))

	return otlptracehttp.New(ctx, opts...)
}

// ShutdownOTel gracefully shuts down OpenTelemetry
func ShutdownOTel(ctx context.Context) error {
	if tracerProvider == nil {
		return nil
	}

	slog.Info("Shutting down OpenTelemetry")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := tracerProvider.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shutdown tracer provider: %w", err)
	}

	slog.Info("OpenTelemetry shutdown complete")
	return nil
}

// GetTracerProvider returns the global tracer provider
func GetTracerProvider() *sdktrace.TracerProvider {
	return tracerProvider
}
