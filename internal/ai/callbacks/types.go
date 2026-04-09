// Package callbacks provides a pluggable callback system for AI gateway observability.
// It supports multiple providers (Langfuse, LangSmith, Helicone, DataDog, OTEL, webhooks)
// with privacy controls and batched async delivery.
package callbacks

import (
	"context"
	"time"

	json "github.com/goccy/go-json"
)

// Callback is the interface that observability adapters must implement.
type Callback interface {
	// Name returns the adapter name (e.g. "langfuse", "webhook").
	Name() string
	// Send delivers a single payload to the observability backend.
	Send(ctx context.Context, payload *CallbackPayload) error
	// Health checks whether the backend is reachable.
	Health() error
}

// CallbackPayload is the structured data sent to each callback adapter.
type CallbackPayload struct {
	RequestID    string            `json:"request_id"`
	WorkspaceID  string            `json:"workspace_id"`
	PrincipalID  string            `json:"principal_id,omitempty"`
	Model        string            `json:"model"`
	Provider     string            `json:"provider"`
	InputTokens  int64             `json:"input_tokens"`
	OutputTokens int64             `json:"output_tokens"`
	TotalTokens  int64             `json:"total_tokens"`
	CostEstimate float64           `json:"cost_estimate,omitempty"`
	Duration     time.Duration     `json:"duration"`
	StatusCode   int               `json:"status_code"`
	Error        string            `json:"error,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	Tags         map[string]string `json:"tags,omitempty"`
	Messages     json.RawMessage   `json:"messages,omitempty"`
	Metadata     map[string]any    `json:"metadata,omitempty"`
}

// CallbackConfig configures a single callback adapter instance.
type CallbackConfig struct {
	// Type selects the adapter: langfuse, langsmith, helicone, datadog, otel, webhook.
	Type string `json:"type"`
	// Endpoint is the URL to send data to.
	Endpoint string `json:"endpoint"`
	// APIKey is the primary API key or public key (depends on adapter).
	APIKey string `json:"api_key,omitempty"`
	// SecretKey is the secondary secret key (used by Langfuse, webhook HMAC).
	SecretKey string `json:"secret_key,omitempty"`
	// BatchSize controls how many payloads to collect before flushing.
	BatchSize int `json:"batch_size,omitempty"`
	// FlushInterval controls the maximum time between flushes.
	FlushInterval time.Duration `json:"flush_interval,omitempty"`
	// PrivacyMode controls what data is sent: "full", "metadata", or "minimal".
	PrivacyMode string `json:"privacy_mode,omitempty"`
	// Enabled controls whether the callback is active.
	Enabled bool `json:"enabled"`
	// Tags are static key-value pairs attached to every payload.
	Tags map[string]string `json:"tags,omitempty"`
}
