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

// LangSmithCallback sends run data to a LangSmith instance.
type LangSmithCallback struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// NewLangSmithCallback creates a LangSmith adapter.
func NewLangSmithCallback(endpoint, apiKey string) *LangSmithCallback {
	return &LangSmithCallback{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "langsmith".
func (ls *LangSmithCallback) Name() string { return "langsmith" }

// langsmithRun is the run object posted to LangSmith.
type langsmithRun struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	RunType     string          `json:"run_type"`
	StartTime   string          `json:"start_time"`
	EndTime     string          `json:"end_time"`
	Inputs      json.RawMessage `json:"inputs,omitempty"`
	Outputs     map[string]any  `json:"outputs,omitempty"`
	Extra       map[string]any  `json:"extra,omitempty"`
	Error       string          `json:"error,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Status      string          `json:"status"`
}

// Send formats the payload as a LangSmith run and POSTs it.
func (ls *LangSmithCallback) Send(ctx context.Context, payload *callbacks.CallbackPayload) error {
	if ctx == nil {
		ctx = context.Background()
	}

	status := "success"
	if payload.Error != "" {
		status = "error"
	}

	tags := make([]string, 0, len(payload.Tags))
	for k, v := range payload.Tags {
		tags = append(tags, k+":"+v)
	}

	run := langsmithRun{
		ID:        payload.RequestID,
		Name:      payload.Provider + "/" + payload.Model,
		RunType:   "llm",
		StartTime: payload.Timestamp.UTC().Format(time.RFC3339Nano),
		EndTime:   payload.Timestamp.Add(payload.Duration).UTC().Format(time.RFC3339Nano),
		Inputs:    payload.Messages,
		Outputs: map[string]any{
			"status_code": payload.StatusCode,
		},
		Extra: map[string]any{
			"model":         payload.Model,
			"provider":      payload.Provider,
			"workspace_id":  payload.WorkspaceID,
			"principal_id":  payload.PrincipalID,
			"input_tokens":  payload.InputTokens,
			"output_tokens": payload.OutputTokens,
			"total_tokens":  payload.TotalTokens,
			"cost_estimate": payload.CostEstimate,
			"duration_ms":   payload.Duration.Milliseconds(),
			"metadata":      payload.Metadata,
		},
		Error:  payload.Error,
		Tags:   tags,
		Status: status,
	}

	body, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("langsmith: marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ls.endpoint+"/runs", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("langsmith: create request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", ls.apiKey)

	resp, err := ls.client.Do(req)
	if err != nil {
		return fmt.Errorf("langsmith: send failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("langsmith: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Health checks connectivity to the LangSmith endpoint.
func (ls *LangSmithCallback) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ls.endpoint+"/health", nil)
	if err != nil {
		return fmt.Errorf("langsmith: health request failed: %w", err)
	}
	req.Header.Set("x-api-key", ls.apiKey)

	resp, err := ls.client.Do(req)
	if err != nil {
		return fmt.Errorf("langsmith: health check failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("langsmith: health check returned %d", resp.StatusCode)
	}
	return nil
}
