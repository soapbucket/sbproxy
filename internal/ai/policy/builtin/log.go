package builtin

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// LogDetector always passes and logs content for audit purposes.
// This detector never triggers (Triggered is always false).
// Config fields:
//   - "max_preview" (int) - maximum characters to include in details preview (default: 200)
//   - "include_stats" (bool) - include character/word count in details (default: true)
type LogDetector struct{}

// Detect logs the content and always returns a non-triggered result.
func (d *LogDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	maxPreview := 200
	if mp, ok := toInt(config.Config["max_preview"]); ok {
		maxPreview = mp
	}

	includeStats := true
	if is, ok := toBool(config.Config["include_stats"]); ok {
		includeStats = is
	}

	charCount := utf8.RuneCountInString(content)

	preview := content
	if charCount > maxPreview {
		runes := []rune(content)
		preview = string(runes[:maxPreview]) + "..."
	}

	if includeStats {
		result.Details = fmt.Sprintf("audit log: %d chars, preview: %s", charCount, preview)
	} else {
		result.Details = fmt.Sprintf("audit log: %s", preview)
	}

	// LogDetector never triggers - it's purely for audit.
	result.Triggered = false
	result.Latency = time.Since(start)
	return result, nil
}
