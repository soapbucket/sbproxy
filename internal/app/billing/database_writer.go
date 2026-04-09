// Package billing tracks and reports usage metrics for metered billing.
package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DatabaseWriter writes metrics to the backend database via HTTP API
type DatabaseWriter struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
}

// NewDatabaseWriter creates a new database metrics writer
func NewDatabaseWriter(baseURL string, apiKey string) *DatabaseWriter {
	return &DatabaseWriter{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// BillingMetricsPayload is the JSON payload sent to the backend
type BillingMetricsPayload struct {
	Metrics []UsageMetricDTO `json:"metrics"`
}

// UsageMetricDTO is the DTO for API transmission
type UsageMetricDTO struct {
	WorkspaceID    string    `json:"workspace_id"`
	OriginID       string    `json:"origin_id"`
	OriginHostname string    `json:"origin_hostname"`
	ProviderName   string    `json:"provider_name,omitempty"`
	Status         string    `json:"status"`
	RequestCount   int64     `json:"request_count"`
	BytesIn        int64     `json:"bytes_in"`
	BytesOut       int64     `json:"bytes_out"`
	BytesBackend   int64     `json:"bytes_backend"`
	BytesFromCache int64     `json:"bytes_from_cache"`
	TokensUsed     int64     `json:"tokens_used"`
	ErrorCount     int64     `json:"error_count"`
	Latency        float64   `json:"latency_seconds"`
	Period         time.Time `json:"period"`
}

// Write sends metrics to the backend
func (dw *DatabaseWriter) Write(ctx context.Context, metrics []UsageMetric) error {
	if len(metrics) == 0 {
		return nil
	}

	// Convert to DTO
	dtos := make([]UsageMetricDTO, len(metrics))
	for i, m := range metrics {
		dtos[i] = UsageMetricDTO{
			WorkspaceID:    m.WorkspaceID,
			OriginID:       m.OriginID,
			OriginHostname: m.OriginHostname,
			ProviderName:   m.ProviderName,
			Status:         m.Status,
			RequestCount:   m.RequestCount,
			BytesIn:        m.BytesIn,
			BytesOut:       m.BytesOut,
			BytesBackend:   m.BytesBackend,
			BytesFromCache: m.BytesFromCache,
			TokensUsed:     m.TokensUsed,
			ErrorCount:     m.ErrorCount,
			Latency:        m.Latency,
			Period:         m.Period,
		}
	}

	payload := BillingMetricsPayload{Metrics: dtos}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/billing/metrics", dw.baseURL), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if dw.apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", dw.apiKey))
	}

	// Send request
	resp, err := dw.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}
	defer resp.Body.Close()

	// Read response body to ensure connection is released
	_, _ = io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backend returned status %d", resp.StatusCode)
	}

	return nil
}

// Close closes the writer
func (dw *DatabaseWriter) Close() error {
	return nil
}
