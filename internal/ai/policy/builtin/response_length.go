package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// ResponseLengthDetector limits the length of response content.
// Config fields:
//   - "max_chars" (int) - maximum character count
//   - "max_words" (int) - maximum word count
//   - "max_lines" (int) - maximum line count
type ResponseLengthDetector struct{}

// Detect checks response content length against configured limits.
func (d *ResponseLengthDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	var violations []string

	if maxChars, ok := toInt(config.Config["max_chars"]); ok {
		charCount := utf8.RuneCountInString(content)
		if charCount > maxChars {
			violations = append(violations, fmt.Sprintf("chars %d > max %d", charCount, maxChars))
		}
	}

	if maxWords, ok := toInt(config.Config["max_words"]); ok {
		wordCount := len(strings.Fields(content))
		if wordCount > maxWords {
			violations = append(violations, fmt.Sprintf("words %d > max %d", wordCount, maxWords))
		}
	}

	if maxLines, ok := toInt(config.Config["max_lines"]); ok {
		lineCount := strings.Count(content, "\n") + 1
		if lineCount > maxLines {
			violations = append(violations, fmt.Sprintf("lines %d > max %d", lineCount, maxLines))
		}
	}

	if len(violations) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("response length exceeded: %s", strings.Join(violations, "; "))
	}

	result.Latency = time.Since(start)
	return result, nil
}
