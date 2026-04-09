package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// AporiaAdapter integrates with Aporia for AI validation.
// API: POST /v1/validate
// Response: {"action": "block"/"passthrough"/"modify", "reason": "..."}
type AporiaAdapter struct{}

// Detect sends content to Aporia and checks the action.
func (a *AporiaAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.aporia.com/v1/validate"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("aporia: %w", err)
	}

	action, _ := resp["action"].(string)
	if action == "block" {
		result.Triggered = true
		reason, _ := resp["reason"].(string)
		if reason != "" {
			result.Details = fmt.Sprintf("Aporia: %s", reason)
		} else {
			result.Details = "blocked by Aporia"
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
