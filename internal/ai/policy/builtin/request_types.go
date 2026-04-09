package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// RequestTypeDetector enforces allowed request types.
// Content should be the request type (e.g., "chat", "completion", "embedding", "image").
// Config fields:
//   - "allowed" ([]string) - list of allowed request types
//   - "blocked" ([]string) - list of blocked request types
type RequestTypeDetector struct{}

// Detect checks if the content (request type) is allowed.
func (d *RequestTypeDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	allowed, _ := toStringSlice(config.Config["allowed"])
	blocked, _ := toStringSlice(config.Config["blocked"])

	reqType := strings.TrimSpace(strings.ToLower(content))

	// Check blocklist first.
	for _, b := range blocked {
		if strings.EqualFold(reqType, b) {
			result.Triggered = true
			result.Details = fmt.Sprintf("request type %q is blocked", reqType)
			result.Latency = time.Since(start)
			return result, nil
		}
	}

	// Check allowlist.
	if len(allowed) > 0 {
		found := false
		for _, a := range allowed {
			if strings.EqualFold(reqType, a) {
				found = true
				break
			}
		}
		if !found {
			result.Triggered = true
			result.Details = fmt.Sprintf("request type %q is not allowed", reqType)
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
