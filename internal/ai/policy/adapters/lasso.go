package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// LassoAdapter integrates with Lasso Security for AI content checking.
// API: POST /v1/check
// Response: {"flagged": true/false, "reason": "..."}
type LassoAdapter struct{}

// Detect sends content to Lasso Security and checks if it was flagged.
func (a *LassoAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.lasso.security/v1/check"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("lasso: %w", err)
	}

	if flagged, ok := resp["flagged"].(bool); ok && flagged {
		result.Triggered = true
		reason, _ := resp["reason"].(string)
		if reason != "" {
			result.Details = fmt.Sprintf("Lasso Security: %s", reason)
		} else {
			result.Details = "flagged by Lasso Security"
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
