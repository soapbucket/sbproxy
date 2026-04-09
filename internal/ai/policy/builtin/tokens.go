package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// TokenEstimatorDetector estimates token count using a simple heuristic and checks bounds.
// Uses a rough estimation of words * 1.3 tokens per word (tiktoken-style approximation).
// Config fields:
//   - "max_tokens" (int) - maximum allowed estimated tokens
//   - "min_tokens" (int) - minimum required estimated tokens
//   - "ratio" (float64) - tokens per word ratio (default: 1.3)
type TokenEstimatorDetector struct{}

// Detect estimates token count and checks against bounds.
func (d *TokenEstimatorDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	ratio := 1.3
	if r, ok := toFloat64(config.Config["ratio"]); ok && r > 0 {
		ratio = r
	}

	wordCount := len(strings.Fields(content))
	estimatedTokens := int(float64(wordCount) * ratio)

	var violations []string

	if maxTokens, ok := toInt(config.Config["max_tokens"]); ok && estimatedTokens > maxTokens {
		violations = append(violations, fmt.Sprintf("estimated tokens %d > max %d", estimatedTokens, maxTokens))
	}

	if minTokens, ok := toInt(config.Config["min_tokens"]); ok && estimatedTokens < minTokens {
		violations = append(violations, fmt.Sprintf("estimated tokens %d < min %d", estimatedTokens, minTokens))
	}

	if len(violations) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("token estimation (words=%d, ratio=%.1f): %s", wordCount, ratio, strings.Join(violations, "; "))
	}

	result.Latency = time.Since(start)
	return result, nil
}
