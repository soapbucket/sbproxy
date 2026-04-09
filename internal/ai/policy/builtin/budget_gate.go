package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// BudgetGateDetector performs a token budget pre-check.
// Content should be a JSON object with "estimated_tokens" and optionally "used_tokens".
// Config fields:
//   - "max_budget" (int) - maximum token budget
//   - "warn_threshold" (float64) - percentage threshold for warning (0.0-1.0, default: 0.8)
type BudgetGateDetector struct{}

// Detect checks if the estimated token usage would exceed the budget.
func (d *BudgetGateDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	maxBudget, hasBudget := toInt(config.Config["max_budget"])
	warnThreshold := 0.8
	if wt, ok := toFloat64(config.Config["warn_threshold"]); ok {
		warnThreshold = wt
	}

	if !hasBudget {
		result.Latency = time.Since(start)
		return result, nil
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		// If content is not JSON, try to estimate from word count.
		wordCount := len(strings.Fields(content))
		estimatedTokens := int(float64(wordCount) * 1.3)
		if estimatedTokens > maxBudget {
			result.Triggered = true
			result.Details = fmt.Sprintf("estimated tokens %d exceeds budget %d", estimatedTokens, maxBudget)
		}
		result.Latency = time.Since(start)
		return result, nil
	}

	estimatedTokens := 0
	if et, ok := toInt(data["estimated_tokens"]); ok {
		estimatedTokens = et
	}

	usedTokens := 0
	if ut, ok := toInt(data["used_tokens"]); ok {
		usedTokens = ut
	}

	totalNeeded := usedTokens + estimatedTokens

	if totalNeeded > maxBudget {
		result.Triggered = true
		result.Details = fmt.Sprintf("total tokens needed %d (used=%d + estimated=%d) exceeds budget %d",
			totalNeeded, usedTokens, estimatedTokens, maxBudget)
	} else if maxBudget > 0 && float64(totalNeeded)/float64(maxBudget) >= warnThreshold {
		result.Triggered = true
		result.Action = policy.GuardrailActionLog
		result.Details = fmt.Sprintf("token usage at %.0f%% of budget (used=%d + estimated=%d / budget=%d)",
			float64(totalNeeded)/float64(maxBudget)*100, usedTokens, estimatedTokens, maxBudget)
	}

	result.Latency = time.Since(start)
	return result, nil
}
