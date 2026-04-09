package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// CrowdStrikeAdapter integrates with CrowdStrike AI Detection and Response (AIDR).
// API: POST /v1/assess
// Response: {"risk_level": "high"/"medium"/"low"/"none", "details": "..."}
type CrowdStrikeAdapter struct{}

// Detect sends content to CrowdStrike AIDR and checks the risk level.
func (a *CrowdStrikeAdapter) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	url := configString(config.Config, "url")
	if url == "" {
		url = "https://api.crowdstrike.com/v1/assess"
	}
	apiKey := configString(config.Config, "api_key")
	minLevel := configString(config.Config, "min_risk_level")
	if minLevel == "" {
		minLevel = "high"
	}

	body := map[string]any{"text": content}
	resp, err := doJSONRequest(ctx, "POST", url, apiKey, body, nil)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("crowdstrike: %w", err)
	}

	riskLevel, _ := resp["risk_level"].(string)
	if isRiskAtOrAbove(riskLevel, minLevel) {
		result.Triggered = true
		result.Details = fmt.Sprintf("CrowdStrike AIDR: risk level %s", riskLevel)
	}

	result.Latency = time.Since(start)
	return result, nil
}

// isRiskAtOrAbove checks if the actual risk level meets or exceeds the minimum.
func isRiskAtOrAbove(actual, minimum string) bool {
	levels := map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	actualLevel, ok1 := levels[actual]
	minLevel, ok2 := levels[minimum]
	if !ok1 || !ok2 {
		return actual == minimum
	}
	return actualLevel >= minLevel
}
