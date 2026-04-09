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

// HeliconeCallback sends log entries to a Helicone instance.
type HeliconeCallback struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// NewHeliconeCallback creates a Helicone adapter.
func NewHeliconeCallback(endpoint, apiKey string) *HeliconeCallback {
	return &HeliconeCallback{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "helicone".
func (h *HeliconeCallback) Name() string { return "helicone" }

// heliconeLogEntry is the log request sent to Helicone.
type heliconeLogEntry struct {
	Request  heliconeRequest  `json:"request"`
	Response heliconeResponse `json:"response"`
	Timing   heliconeTiming   `json:"timing"`
}

type heliconeRequest struct {
	ID         string            `json:"id"`
	Model      string            `json:"model"`
	Provider   string            `json:"provider"`
	Body       json.RawMessage   `json:"body,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type heliconeResponse struct {
	StatusCode int            `json:"status"`
	Body       map[string]any `json:"body,omitempty"`
}

type heliconeTiming struct {
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`
	LatencyMS int64  `json:"latencyMs"`
}

// Send formats the payload as a Helicone log entry and POSTs it.
func (h *HeliconeCallback) Send(ctx context.Context, payload *callbacks.CallbackPayload) error {
	if ctx == nil {
		ctx = context.Background()
	}

	properties := make(map[string]string, len(payload.Tags)+3)
	for k, v := range payload.Tags {
		properties[k] = v
	}
	properties["workspace_id"] = payload.WorkspaceID
	properties["principal_id"] = payload.PrincipalID
	properties["request_id"] = payload.RequestID

	entry := heliconeLogEntry{
		Request: heliconeRequest{
			ID:         payload.RequestID,
			Model:      payload.Model,
			Provider:   payload.Provider,
			Body:       payload.Messages,
			Properties: properties,
		},
		Response: heliconeResponse{
			StatusCode: payload.StatusCode,
			Body: map[string]any{
				"usage": map[string]any{
					"prompt_tokens":     payload.InputTokens,
					"completion_tokens": payload.OutputTokens,
					"total_tokens":      payload.TotalTokens,
				},
				"cost":  payload.CostEstimate,
				"error": payload.Error,
			},
		},
		Timing: heliconeTiming{
			StartTime: payload.Timestamp.UTC().Format(time.RFC3339Nano),
			EndTime:   payload.Timestamp.Add(payload.Duration).UTC().Format(time.RFC3339Nano),
			LatencyMS: payload.Duration.Milliseconds(),
		},
	}

	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("helicone: marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint+"/v1/log/request", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("helicone: create request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Helicone-Auth", "Bearer "+h.apiKey)

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("helicone: send failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("helicone: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Health checks connectivity to the Helicone endpoint.
func (h *HeliconeCallback) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.endpoint+"/v1/health", nil)
	if err != nil {
		return fmt.Errorf("helicone: health request failed: %w", err)
	}
	req.Header.Set("Helicone-Auth", "Bearer "+h.apiKey)

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("helicone: health check failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("helicone: health check returned %d", resp.StatusCode)
	}
	return nil
}
