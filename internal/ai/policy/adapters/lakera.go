package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// LakeraAdapter integrates with Lakera Guard for prompt injection detection.
// API: POST /v1/guard with {"input": content}
// Response: {"results": [{"flagged": true/false, "categories": {...}}]}
type LakeraAdapter struct{}

// Detect sends content to Lakera Guard and checks if it was flagged.
func (a *LakeraAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.lakera.ai/v1/guard"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"input": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("lakera: %w", err)
	}

	// Parse results[0].flagged
	if results, ok := resp["results"].([]any); ok && len(results) > 0 {
		if first, ok := results[0].(map[string]any); ok {
			if flagged, ok := first["flagged"].(bool); ok && flagged {
				result.Triggered = true
				result.Details = "prompt injection detected by Lakera Guard"
				if cats, ok := first["categories"].(map[string]any); ok {
					for cat, v := range cats {
						if triggered, ok := v.(bool); ok && triggered {
							result.Details = fmt.Sprintf("Lakera Guard: %s detected", cat)
							break
						}
					}
				}
			}
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
