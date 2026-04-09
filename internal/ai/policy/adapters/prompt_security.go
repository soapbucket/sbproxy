package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// PromptSecurityAdapter integrates with Prompt Security for injection detection.
// API: POST /v1/protect
// Response: {"injection_detected": true/false, "confidence": 0.0-1.0}
type PromptSecurityAdapter struct{}

// Detect sends content to Prompt Security and checks for injection.
func (a *PromptSecurityAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.prompt.security/v1/protect"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"prompt": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("prompt_security: %w", err)
	}

	if detected, ok := resp["injection_detected"].(bool); ok && detected {
		result.Triggered = true
		confidence := configFloat64(resp, "confidence", 0)
		result.Details = fmt.Sprintf("Prompt Security: injection detected (confidence: %.2f)", confidence)
	}

	result.Latency = time.Since(start)
	return result, nil
}
