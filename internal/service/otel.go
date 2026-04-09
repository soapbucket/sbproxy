// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"context"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/telemetry"
)

func initOTel(ctx context.Context) error {
	otelConfig := globalConfig.OTelConfig

	config := telemetry.OTelConfig{
		Enabled:        otelConfig.Enabled,
		OTLPEndpoint:   otelConfig.OTLPEndpoint,
		OTLPProtocol:   otelConfig.OTLPProtocol,
		OTLPInsecure:   otelConfig.OTLPInsecure,
		ServiceName:    otelConfig.ServiceName,
		ServiceVersion: otelConfig.ServiceVersion,
		Environment:    otelConfig.Environment,
		SampleRate:     otelConfig.SampleRate,
		Headers:        otelConfig.Headers,
	}

	return telemetry.InitializeOTel(ctx, config)
}

func shutdownOTel() error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return telemetry.ShutdownOTel(shutdownCtx)
}
