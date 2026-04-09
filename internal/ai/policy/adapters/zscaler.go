package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// ZscalerAdapter integrates with Zscaler for threat scanning.
// API: POST /v1/scan
// Response: {"threat_detected": true/false, "threat_type": "...", "details": "..."}
type ZscalerAdapter struct{}

// Detect sends content to Zscaler and checks for threat detection.
func (a *ZscalerAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.zscaler.com/v1/scan"
	}
	apiKey := configString(config.Config, "api_key")

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("zscaler: %w", err)
	}

	if detected, ok := resp["threat_detected"].(bool); ok && detected {
		result.Triggered = true
		threatType, _ := resp["threat_type"].(string)
		if threatType != "" {
			result.Details = fmt.Sprintf("Zscaler: threat type %s detected", threatType)
		} else {
			result.Details = "threat detected by Zscaler"
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
