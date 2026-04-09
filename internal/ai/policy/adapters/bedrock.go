package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// BedrockAdapter integrates with AWS Bedrock Guardrails.
// API: POST with {"source": "INPUT"/"OUTPUT", "content": [{"text": {"text": content}}]}
// Response: {"action": "BLOCKED"/"ALLOWED", "outputs": [...]}
type BedrockAdapter struct{}

// Detect sends content to AWS Bedrock Guardrails and checks the action.
func (a *BedrockAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	apiKey := configString(config.Config, "api_key")
	source := configString(config.Config, "source")
	if source == "" {
		source = "INPUT"
	}

	if url == "" {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("bedrock: missing url in config")
	}

	body := map[string]any{
		"source": source,
		"content": []map[string]any{
			{"text": map[string]string{"text": content}},
		},
	}

	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("bedrock: %w", err)
	}

	if action, ok := resp["action"].(string); ok && action == "BLOCKED" {
		result.Triggered = true
		result.Details = "blocked by AWS Bedrock Guardrails"
		if outputs, ok := resp["outputs"].([]any); ok && len(outputs) > 0 {
			if out, ok := outputs[0].(map[string]any); ok {
				if text, ok := out["text"].(string); ok {
					result.Details = fmt.Sprintf("Bedrock: %s", text)
				}
			}
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
