package builtin

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// KeywordDetector detects keywords/phrases in content using exact match or glob patterns.
// Config fields:
//   - "keywords" ([]string) - list of keywords or glob patterns to match
//   - "case_sensitive" (bool) - whether matching is case-sensitive (default: false)
//   - "mode" (string) - "exact" (default) or "glob"
type KeywordDetector struct{}

// Detect checks content for keyword or glob matches.
func (d *KeywordDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	keywords, _ := toStringSlice(config.Config["keywords"])
	caseSensitive, _ := toBool(config.Config["case_sensitive"])
	mode, _ := toString(config.Config["mode"])
	if mode == "" {
		mode = "exact"
	}

	checkContent := content
	if !caseSensitive {
		checkContent = strings.ToLower(content)
	}

	var matched []string
	for _, kw := range keywords {
		checkKw := kw
		if !caseSensitive {
			checkKw = strings.ToLower(kw)
		}

		switch mode {
		case "glob":
			// Split content into words and check each against the glob pattern.
			words := strings.Fields(checkContent)
			for _, word := range words {
				if ok, _ := filepath.Match(checkKw, word); ok {
					matched = append(matched, kw)
					break
				}
			}
		default:
			if strings.Contains(checkContent, checkKw) {
				matched = append(matched, kw)
			}
		}
	}

	if len(matched) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("matched keywords: %s", strings.Join(matched, ", "))
	}

	result.Latency = time.Since(start)
	return result, nil
}
