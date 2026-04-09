package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// F5Adapter integrates with F5 Guardrails for content inspection.
// API: POST /v1/inspect
// Response: {"decision": "block"/"allow"/"warn", "details": "..."}
type F5Adapter struct{}

// Detect sends content to F5 Guardrails and checks the decision.
func (a *F5Adapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.f5.com/v1/inspect"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("f5: %w", err)
	}

	decision, _ := resp["decision"].(string)
	if decision == "block" || decision == "warn" {
		result.Triggered = true
		details, _ := resp["details"].(string)
		if details != "" {
			result.Details = fmt.Sprintf("F5 Guardrails: %s - %s", decision, details)
		} else {
			result.Details = fmt.Sprintf("F5 Guardrails decision: %s", decision)
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
