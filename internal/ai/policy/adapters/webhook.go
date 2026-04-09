package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// WebhookAdapter is a generic webhook adapter for custom guardrail endpoints.
// API: POST JSON to configured URL
// Response: checks for "flagged" or "blocked" boolean fields.
type WebhookAdapter struct{}

// Detect sends content to the configured webhook URL and checks the response.
func (a *WebhookAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("webhook: missing url in config")
	}
	apiKey := configString(config.Config, "api_key")
	method := configString(config.Config, "method")
	if method == "" {
		method = "POST"
	}

	// Build configurable request body.
	bodyField := configString(config.Config, "body_field")
	if bodyField == "" {
		bodyField = "text"
	}
	body := map[string]any{bodyField: content}

	// Support custom headers.
	customHeaders := make(map[string]string)
	if hdrs, ok := config.Config["headers"].(map[string]any); ok {
		for k, v := range hdrs {
			if s, ok := v.(string); ok {
				customHeaders[k] = s
			}
		}
	}

	resp, err := doJSONRequest(ctx, method, url, apiKey, body, customHeaders)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("webhook: %w", err)
	}

	// Check "flagged" field first, then "blocked".
	triggered := false
	if flagged, ok := resp["flagged"].(bool); ok && flagged {
		triggered = true
	} else if blocked, ok := resp["blocked"].(bool); ok && blocked {
		triggered = true
	}

	// Support custom response field.
	if responseField := configString(config.Config, "response_field"); responseField != "" {
		if val, ok := resp[responseField].(bool); ok && val {
			triggered = true
		}
	}

	if triggered {
		result.Triggered = true
		if reason, ok := resp["reason"].(string); ok {
			result.Details = reason
		} else if details, ok := resp["details"].(string); ok {
			result.Details = details
		} else {
			result.Details = "flagged by webhook guardrail"
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
