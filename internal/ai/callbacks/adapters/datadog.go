package adapters

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/callbacks"
)

// DataDogCallback sends metrics and logs to DataDog.
type DataDogCallback struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// NewDataDogCallback creates a DataDog adapter.
func NewDataDogCallback(endpoint, apiKey string) *DataDogCallback {
	return &DataDogCallback{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "datadog".
func (d *DataDogCallback) Name() string { return "datadog" }

// datadogLogEntry is the log entry sent to DataDog.
type datadogLogEntry struct {
	Ddsource string            `json:"ddsource"`
	Ddtags   string            `json:"ddtags"`
	Hostname string            `json:"hostname"`
	Message  string            `json:"message"`
	Service  string            `json:"service"`
	Status   string            `json:"status"`
	AI       datadogAIFields   `json:"ai"`
	Tags     map[string]string `json:"tags,omitempty"`
}

type datadogAIFields struct {
	RequestID    string  `json:"request_id"`
	WorkspaceID  string  `json:"workspace_id"`
	Provider     string  `json:"provider"`
	Model        string  `json:"model"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalTokens  int64   `json:"total_tokens"`
	CostEstimate float64 `json:"cost_estimate"`
	DurationMS   int64   `json:"duration_ms"`
	StatusCode   int     `json:"status_code"`
	Error        string  `json:"error,omitempty"`
}

// Send formats the payload as a DataDog log entry and POSTs it.
func (d *DataDogCallback) Send(ctx context.Context, payload *callbacks.CallbackPayload) error {
	if ctx == nil {
		ctx = context.Background()
	}

	status := "info"
	if payload.StatusCode >= 500 {
		status = "error"
	} else if payload.StatusCode >= 400 {
		status = "warn"
	}

	// Build tags string for ddtags.
	ddtags := fmt.Sprintf("provider:%s,model:%s,workspace:%s", payload.Provider, payload.Model, payload.WorkspaceID)

	entry := []datadogLogEntry{{
		Ddsource: "soapbucket-proxy",
		Ddtags:   ddtags,
		Hostname: "proxy",
		Message:  fmt.Sprintf("AI request %s %s/%s %d", payload.RequestID, payload.Provider, payload.Model, payload.StatusCode),
		Service:  "ai-gateway",
		Status:   status,
		AI: datadogAIFields{
			RequestID:    payload.RequestID,
			WorkspaceID:  payload.WorkspaceID,
			Provider:     payload.Provider,
			Model:        payload.Model,
			InputTokens:  payload.InputTokens,
			OutputTokens: payload.OutputTokens,
			TotalTokens:  payload.TotalTokens,
			CostEstimate: payload.CostEstimate,
			DurationMS:   payload.Duration.Milliseconds(),
			StatusCode:   payload.StatusCode,
			Error:        payload.Error,
		},
		Tags: payload.Tags,
	}}

	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("datadog: marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint+"/v1/input", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("datadog: create request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", d.apiKey)

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("datadog: send failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("datadog: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Health checks connectivity to the DataDog endpoint.
func (d *DataDogCallback) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.endpoint+"/v1/validate", nil)
	if err != nil {
		return fmt.Errorf("datadog: health request failed: %w", err)
	}
	req.Header.Set("DD-API-KEY", d.apiKey)

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("datadog: health check failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("datadog: health check returned %d", resp.StatusCode)
	}
	return nil
}
