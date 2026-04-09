package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// PatronusAdapter integrates with Patronus AI for evaluation.
// API: POST /v1/evaluate
// Response: {"pass": true/false, "score": 0.0-1.0, "explanation": "..."}
type PatronusAdapter struct{}

// Detect sends content to Patronus and checks if evaluation passed.
func (a *PatronusAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.patronus.ai/v1/evaluate"
	}
	apiKey := configString(config.Config, "api_key")
	evaluator := configString(config.Config, "evaluator")

	body := map[string]any{
		"text":      content,
		"evaluator": evaluator,
	}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("patronus: %w", err)
	}

	// Patronus uses pass == false to indicate a problem.
	if pass, ok := resp["pass"].(bool); ok && !pass {
		result.Triggered = true
		explanation, _ := resp["explanation"].(string)
		if explanation != "" {
			result.Details = fmt.Sprintf("Patronus: %s", explanation)
		} else {
			result.Details = "evaluation failed by Patronus"
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
