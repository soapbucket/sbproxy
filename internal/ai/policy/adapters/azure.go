package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// AzureAdapter integrates with Azure Content Safety.
// API: POST /contentsafety/text:analyze?api-version=2024-09-01
// Response: {"categoriesAnalysis": [{"category": "...", "severity": 0-6}]}
type AzureAdapter struct{}

// Detect sends content to Azure Content Safety and checks severity thresholds.
func (a *AzureAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	apiKey := configString(config.Config, "api_key")
	threshold := configFloat64(config.Config, "threshold", 2)

	if url == "" {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("azure: missing url in config")
	}

	body := map[string]any{
		"text": content,
	}

	headers := map[string]string{
		"Ocp-Apim-Subscription-Key": apiKey,
	}

	// Azure uses subscription key, not Bearer token.
	resp, err := doJSONRequest(ctx, "POST", url, "", body, headers)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("azure: %w", err)
	}

	if categories, ok := resp["categoriesAnalysis"].([]any); ok {
		for _, cat := range categories {
			if c, ok := cat.(map[string]any); ok {
				severity := configFloat64(c, "severity", 0)
				if severity > threshold {
					result.Triggered = true
					category := ""
					if name, ok := c["category"].(string); ok {
						category = name
					}
					result.Details = fmt.Sprintf("Azure Content Safety: %s severity %.0f exceeds threshold %.0f", category, severity, threshold)
					break
				}
			}
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
