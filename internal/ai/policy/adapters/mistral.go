package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// MistralAdapter integrates with Mistral's moderation API.
// API: POST /v1/moderations
// Response: {"results": [{"categories": {"sexual": true, ...}, "category_scores": {"sexual": 0.99, ...}}]}
type MistralAdapter struct{}

// Detect sends content to Mistral Moderation and checks category scores.
func (a *MistralAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.mistral.ai/v1/moderations"
	}
	apiKey := configString(config.Config, "api_key")
	threshold := configFloat64(config.Config, "threshold", 0.7)

	body := map[string]any{
		"model": "mistral-moderation-latest",
		"input": content,
	}

	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("mistral: %w", err)
	}

	if results, ok := resp["results"].([]any); ok && len(results) > 0 {
		if first, ok := results[0].(map[string]any); ok {
			// Check category_scores against threshold.
			if scores, ok := first["category_scores"].(map[string]any); ok {
				for category, scoreVal := range scores {
					score := configFloat64(map[string]any{"s": scoreVal}, "s", 0)
					if score >= threshold {
						result.Triggered = true
						result.Details = fmt.Sprintf("Mistral Moderation: %s score %.2f exceeds threshold %.2f", category, score, threshold)
						break
					}
				}
			}
			// Also check boolean categories as fallback.
			if !result.Triggered {
				if categories, ok := first["categories"].(map[string]any); ok {
					for category, flagged := range categories {
						if f, ok := flagged.(bool); ok && f {
							result.Triggered = true
							result.Details = fmt.Sprintf("Mistral Moderation: %s flagged", category)
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
