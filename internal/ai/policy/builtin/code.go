package builtin

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// CodeDetector detects code snippets in content.
// Detects: SQL, Python, JavaScript, Go, shell commands.
// Config fields:
//   - "languages" ([]string) - optional filter for which languages to detect
//   - "mode" (string) - "block" to trigger when code is found, "require" to trigger when not found
type CodeDetector struct{}

// codePattern holds a language name and its detection patterns.
type codePattern struct {
	name     string
	patterns []*regexp.Regexp
}

var codePatterns = []codePattern{
	{
		name: "sql",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*(FROM|INTO|TABLE|SET|WHERE)\b`),
			regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\b`),
		},
	},
	{
		name: "python",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`\bdef\s+\w+\s*\(.*\)\s*(->\s*\w+\s*)?:`),
			regexp.MustCompile(`\bimport\s+\w+|from\s+\w+\s+import\b`),
			regexp.MustCompile(`\bclass\s+\w+.*:\s*$`),
		},
	},
	{
		name: "javascript",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`\b(const|let|var)\s+\w+\s*=`),
			regexp.MustCompile(`\bfunction\s+\w+\s*\(`),
			regexp.MustCompile(`=>\s*\{`),
			regexp.MustCompile(`\bconsole\.(log|error|warn)\s*\(`),
		},
	},
	{
		name: "go",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`\bfunc\s+(\(\w+\s+\*?\w+\)\s+)?\w+\s*\(`),
			regexp.MustCompile(`\bpackage\s+\w+\b`),
			regexp.MustCompile(`\bif\s+err\s*!=\s*nil\s*\{`),
		},
	},
	{
		name: "shell",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`^\s*#!/bin/(bash|sh|zsh)`),
			regexp.MustCompile(`\b(sudo|chmod|chown|curl|wget|apt-get|yum|pip)\s+`),
			regexp.MustCompile(`\|\s*(grep|awk|sed|sort|uniq|wc)\b`),
		},
	},
}

// Detect checks content for code patterns.
func (d *CodeDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	languages, _ := toStringSlice(config.Config["languages"])
	mode, _ := toString(config.Config["mode"])
	if mode == "" {
		mode = "block"
	}

	langSet := make(map[string]bool, len(languages))
	for _, l := range languages {
		langSet[strings.ToLower(l)] = true
	}
	checkAll := len(languages) == 0

	var detected []string
	for _, cp := range codePatterns {
		if !checkAll && !langSet[cp.name] {
			continue
		}
		for _, pat := range cp.patterns {
			if pat.MatchString(content) {
				detected = append(detected, cp.name)
				break
			}
		}
	}

	switch mode {
	case "require":
		if len(detected) == 0 {
			result.Triggered = true
			result.Details = "no code detected (code is required)"
		}
	default:
		if len(detected) > 0 {
			result.Triggered = true
			result.Details = fmt.Sprintf("code detected: %s", strings.Join(detected, ", "))
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}
