package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// GCPModelArmorAdapter integrates with GCP Model Armor.
// API: POST /v1/projects/{project}/locations/{location}/modelArmor:analyze
// Response: {"blocked": true/false, "findings": [...]}
type GCPModelArmorAdapter struct{}

// Detect sends content to GCP Model Armor and checks if it was blocked.
func (a *GCPModelArmorAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	apiKey := configString(config.Config, "api_key")

	if url == "" {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("gcp_model_armor: missing url in config")
	}

	body := map[string]any{
		"userPromptData": map[string]any{
			"text": content,
		},
	}

	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("gcp_model_armor: %w", err)
	}

	if blocked, ok := resp["blocked"].(bool); ok && blocked {
		result.Triggered = true
		result.Details = "blocked by GCP Model Armor"
	}

	result.Latency = time.Since(start)
	return result, nil
}
