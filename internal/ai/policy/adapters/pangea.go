package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// PangeaAdapter integrates with Pangea AI Guard for content detection.
// API: POST /v1/ai/guard/text/detect
// Response: {"result": {"detected": true/false, "findings": [...]}}
type PangeaAdapter struct{}

// Detect sends content to Pangea AI Guard and checks for detections.
func (a *PangeaAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://ai-guard.aws.us.pangea.cloud/v1/ai/guard/text/detect"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("pangea: %w", err)
	}

	if r, ok := resp["result"].(map[string]any); ok {
		if detected, ok := r["detected"].(bool); ok && detected {
			result.Triggered = true
			result.Details = "content detected by Pangea AI Guard"
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
