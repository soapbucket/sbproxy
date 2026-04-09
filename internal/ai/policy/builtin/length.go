package builtin

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// LengthDetector checks content length against min/max bounds.
// Config fields:
//   - "min_chars" (int) - minimum character count
//   - "max_chars" (int) - maximum character count
//   - "min_words" (int) - minimum word count
//   - "max_words" (int) - maximum word count
//   - "min_sentences" (int) - minimum sentence count
//   - "max_sentences" (int) - maximum sentence count
type LengthDetector struct{}

// Detect checks content against length constraints.
func (d *LengthDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	var violations []string

	charCount := utf8.RuneCountInString(content)
	wordCount := len(strings.Fields(content))
	sentenceCount := countSentences(content)

	if minChars, ok := toInt(config.Config["min_chars"]); ok && charCount < minChars {
		violations = append(violations, fmt.Sprintf("chars %d < min %d", charCount, minChars))
	}
	if maxChars, ok := toInt(config.Config["max_chars"]); ok && charCount > maxChars {
		violations = append(violations, fmt.Sprintf("chars %d > max %d", charCount, maxChars))
	}
	if minWords, ok := toInt(config.Config["min_words"]); ok && wordCount < minWords {
		violations = append(violations, fmt.Sprintf("words %d < min %d", wordCount, minWords))
	}
	if maxWords, ok := toInt(config.Config["max_words"]); ok && wordCount > maxWords {
		violations = append(violations, fmt.Sprintf("words %d > max %d", wordCount, maxWords))
	}
	if minSentences, ok := toInt(config.Config["min_sentences"]); ok && sentenceCount < minSentences {
		violations = append(violations, fmt.Sprintf("sentences %d < min %d", sentenceCount, minSentences))
	}
	if maxSentences, ok := toInt(config.Config["max_sentences"]); ok && sentenceCount > maxSentences {
		violations = append(violations, fmt.Sprintf("sentences %d > max %d", sentenceCount, maxSentences))
	}

	if len(violations) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("length violations: %s", strings.Join(violations, "; "))
	}

	result.Latency = time.Since(start)
	return result, nil
}

// countSentences counts sentences by looking for sentence-ending punctuation.
func countSentences(s string) int {
	if strings.TrimSpace(s) == "" {
		return 0
	}
	count := 0
	for _, r := range s {
		if r == '.' || r == '!' || r == '?' {
			count++
		}
	}
	// If no sentence-ending punctuation found, count as 1 sentence if non-empty.
	if count == 0 {
		return 1
	}
	return count
}
