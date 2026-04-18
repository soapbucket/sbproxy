// Package telemetry collects and exports distributed tracing and observability data.
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// OTLPConfig configures OTLP export.
type OTLPConfig struct {
	Endpoint    string            `json:"endpoint" yaml:"endpoint"`
	Headers     map[string]string `json:"headers,omitempty" yaml:"headers"`
	TimeoutSecs int               `json:"timeout_secs,omitempty" yaml:"timeout_secs"`
	Insecure    bool              `json:"insecure,omitempty" yaml:"insecure"`
}

// spanPayload is the JSON wire format for a span sent to the OTLP endpoint.
// It mirrors the fields of the internal Span type but adds JSON tags for export.
type spanPayload struct {
	TraceID    string            `json:"trace_id"`
	SpanID     string            `json:"span_id"`
	ParentID   string            `json:"parent_id,omitempty"`
	Name       string            `json:"name"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// toPayload converts an internal Span to the JSON export format.
func toPayload(s *Span) spanPayload {
	return spanPayload{
		TraceID:    s.TraceID,
		SpanID:     s.SpanID,
		ParentID:   s.ParentID,
		Name:       s.Name,
		StartTime:  s.StartTime,
		EndTime:    s.EndTime,
		Attributes: s.Attrs(),
	}
}

// OTLPExporter sends traces and metrics to an OTLP-compatible endpoint via HTTP.
type OTLPExporter struct {
	config OTLPConfig
	client *http.Client
	mu     sync.Mutex
}

// NewOTLPExporter creates a new OTLP HTTP exporter with the given configuration.
// If TimeoutSecs is 0, it defaults to 10 seconds.
func NewOTLPExporter(cfg OTLPConfig) *OTLPExporter {
	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &OTLPExporter{
		config: cfg,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// ExportSpans sends a batch of spans to the OTLP traces endpoint.
// The spans are serialized as JSON and POSTed to {endpoint}/v1/traces.
func (e *OTLPExporter) ExportSpans(ctx context.Context, spans []*Span) error {
	if len(spans) == 0 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	payloads := make([]spanPayload, len(spans))
	for i, s := range spans {
		payloads[i] = toPayload(s)
	}

	payload, err := json.Marshal(payloads)
	if err != nil {
		return fmt.Errorf("failed to marshal spans: %w", err)
	}

	url := e.config.Endpoint + "/v1/traces"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send spans: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OTLP endpoint returned status %d", resp.StatusCode)
	}

	slog.Debug("exported spans to OTLP",
		"count", len(spans),
		"endpoint", url)

	return nil
}

// Close flushes pending exports and releases resources.
func (e *OTLPExporter) Close() error {
	e.client.CloseIdleConnections()
	return nil
}
