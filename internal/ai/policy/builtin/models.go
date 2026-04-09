package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// ModelDetector checks if the content (model name) is in an allowlist or blocklist.
// Config fields:
//   - "allowed" ([]string) - list of allowed model names/prefixes
//   - "blocked" ([]string) - list of blocked model names/prefixes
//   - "prefix_match" (bool) - if true, match by prefix instead of exact match
type ModelDetector struct{}

// Detect checks if the content (model name) matches the allowed/blocked lists.
func (d *ModelDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	allowed, _ := toStringSlice(config.Config["allowed"])
	blocked, _ := toStringSlice(config.Config["blocked"])
	prefixMatch, _ := toBool(config.Config["prefix_match"])

	model := strings.TrimSpace(content)

	// Check blocklist first.
	if len(blocked) > 0 {
		for _, b := range blocked {
			if matchModel(model, b, prefixMatch) {
				result.Triggered = true
				result.Details = fmt.Sprintf("model %q is blocked", model)
				result.Latency = time.Since(start)
				return result, nil
			}
		}
	}

	// Check allowlist.
	if len(allowed) > 0 {
		found := false
		for _, a := range allowed {
			if matchModel(model, a, prefixMatch) {
				found = true
				break
			}
		}
		if !found {
			result.Triggered = true
			result.Details = fmt.Sprintf("model %q is not in allowed list", model)
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}

// matchModel checks if a model name matches a pattern.
func matchModel(model, pattern string, prefixMatch bool) bool {
	if prefixMatch {
		return strings.HasPrefix(strings.ToLower(model), strings.ToLower(pattern))
	}
	return strings.EqualFold(model, pattern)
}
