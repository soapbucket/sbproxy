package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// QualifireAdapter integrates with Qualifire for content checking.
// API: POST /v1/check
// Response: {"safe": true/false, "details": "..."}
type QualifireAdapter struct{}

// Detect sends content to Qualifire and checks the safe field.
func (a *QualifireAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.qualifire.ai/v1/check"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("qualifire: %w", err)
	}

	// safe == false means content was flagged.
	if safe, ok := resp["safe"].(bool); ok && !safe {
		result.Triggered = true
		details, _ := resp["details"].(string)
		if details != "" {
			result.Details = fmt.Sprintf("Qualifire: %s", details)
		} else {
			result.Details = "flagged by Qualifire"
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
