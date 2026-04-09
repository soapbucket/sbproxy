package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// WalledAdapter integrates with Walled AI for content guarding.
// API: POST /v1/guard
// Response: {"blocked": true/false, "categories": [...]}
type WalledAdapter struct{}

// Detect sends content to Walled AI and checks if it was blocked.
func (a *WalledAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.walled.ai/v1/guard"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("walled: %w", err)
	}

	if blocked, ok := resp["blocked"].(bool); ok && blocked {
		result.Triggered = true
		result.Details = "blocked by Walled AI"
	}

	result.Latency = time.Since(start)
	return result, nil
}
