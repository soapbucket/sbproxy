package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// PillarAdapter integrates with Pillar Security for AI risk scanning.
// API: POST /v1/scan
// Response: {"risk_score": 0.0-1.0, "findings": [...]}
type PillarAdapter struct{}

// Detect sends content to Pillar Security and checks the risk score.
func (a *PillarAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.pillar.security/v1/scan"
	}
	apiKey := configString(config.Config, "api_key")
	threshold := configFloat64(config.Config, "threshold", 0.7)

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("pillar: %w", err)
	}

	riskScore := configFloat64(resp, "risk_score", 0)
	if riskScore > threshold {
		result.Triggered = true
		result.Details = fmt.Sprintf("Pillar Security risk score %.2f exceeds threshold %.2f", riskScore, threshold)
	}

	result.Latency = time.Since(start)
	return result, nil
}
