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

// LangfuseCallback sends traces to a Langfuse instance via the ingestion API.
type LangfuseCallback struct {
	endpoint  string
	publicKey string
	secretKey string
	client    *http.Client
}

// NewLangfuseCallback creates a Langfuse adapter.
func NewLangfuseCallback(endpoint, publicKey, secretKey string) *LangfuseCallback {
	return &LangfuseCallback{
		endpoint:  endpoint,
		publicKey: publicKey,
		secretKey: secretKey,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "langfuse".
func (l *LangfuseCallback) Name() string { return "langfuse" }

// langfuseEvent is a single event in the Langfuse ingestion batch.
type langfuseEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Body      any    `json:"body"`
}

// langfuseTrace is the trace body for Langfuse.
type langfuseTrace struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Metadata map[string]any    `json:"metadata,omitempty"`
	Tags     []string          `json:"tags,omitempty"`
	Input    json.RawMessage   `json:"input,omitempty"`
	Output   any               `json:"output,omitempty"`
}

// langfuseGeneration is the generation body for Langfuse.
type langfuseGeneration struct {
	ID             string          `json:"id"`
	TraceID        string          `json:"traceId"`
	Name           string          `json:"name"`
	Model          string          `json:"model,omitempty"`
	ModelParameters map[string]any `json:"modelParameters,omitempty"`
	Input          json.RawMessage `json:"input,omitempty"`
	Output         any             `json:"output,omitempty"`
	Usage          map[string]any  `json:"usage,omitempty"`
	Metadata       map[string]any  `json:"metadata,omitempty"`
	StartTime      string          `json:"startTime"`
	EndTime        string          `json:"endTime"`
	StatusMessage  string          `json:"statusMessage,omitempty"`
	Level          string          `json:"level,omitempty"`
}

// langfuseIngestion is the top-level ingestion request.
type langfuseIngestion struct {
	Batch []langfuseEvent `json:"batch"`
}

// Send formats the payload as Langfuse trace + generation events and POSTs them.
func (l *LangfuseCallback) Send(ctx context.Context, payload *callbacks.CallbackPayload) error {
	if ctx == nil {
		ctx = context.Background()
	}

	traceID := payload.RequestID
	genID := payload.RequestID + "-gen"
	ts := payload.Timestamp.UTC().Format(time.RFC3339Nano)
	endTime := payload.Timestamp.Add(payload.Duration).UTC().Format(time.RFC3339Nano)

	tags := make([]string, 0, len(payload.Tags))
	for k, v := range payload.Tags {
		tags = append(tags, k+":"+v)
	}

	level := "DEFAULT"
	if payload.Error != "" {
		level = "ERROR"
	}

	ingestion := langfuseIngestion{
		Batch: []langfuseEvent{
			{
				ID:        traceID,
				Type:      "trace-create",
				Timestamp: ts,
				Body: langfuseTrace{
					ID:   traceID,
					Name: payload.Provider + "/" + payload.Model,
					Metadata: map[string]any{
						"workspace_id": payload.WorkspaceID,
						"principal_id": payload.PrincipalID,
						"provider":     payload.Provider,
						"status_code":  payload.StatusCode,
					},
					Tags:  tags,
					Input: payload.Messages,
				},
			},
			{
				ID:        genID,
				Type:      "generation-create",
				Timestamp: ts,
				Body: langfuseGeneration{
					ID:      genID,
					TraceID: traceID,
					Name:    "completion",
					Model:   payload.Model,
					Input:   payload.Messages,
					Usage: map[string]any{
						"input":       payload.InputTokens,
						"output":      payload.OutputTokens,
						"total":       payload.TotalTokens,
						"totalCost":   payload.CostEstimate,
					},
					Metadata:      payload.Metadata,
					StartTime:     ts,
					EndTime:       endTime,
					StatusMessage: payload.Error,
					Level:         level,
				},
			},
		},
	}

	body, err := json.Marshal(ingestion)
	if err != nil {
		return fmt.Errorf("langfuse: marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.endpoint+"/api/public/ingestion", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("langfuse: create request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(l.publicKey, l.secretKey)

	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("langfuse: send failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("langfuse: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Health checks connectivity to the Langfuse endpoint.
func (l *LangfuseCallback) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.endpoint+"/api/public/health", nil)
	if err != nil {
		return fmt.Errorf("langfuse: health request failed: %w", err)
	}
	req.SetBasicAuth(l.publicKey, l.secretKey)

	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("langfuse: health check failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("langfuse: health check returned %d", resp.StatusCode)
	}
	return nil
}
