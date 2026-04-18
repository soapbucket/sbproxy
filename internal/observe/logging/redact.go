// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"regexp"
	"strings"
)

// redactPlaceholder is the replacement string for detected secrets.
const redactPlaceholder = "[REDACTED]"

// SecretPatterns defines regex patterns for known secret formats. Each pattern
// matches a common credential format that should never appear in log output.
var SecretPatterns = []*regexp.Regexp{
	// OpenAI API keys (sk-proj and sk- prefixed).
	regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
	// GitHub personal access tokens.
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	// GitHub fine-grained tokens.
	regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{80,}`),
	// AWS access key IDs.
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	// Bearer tokens in authorization headers.
	regexp.MustCompile(`Bearer\s+[a-zA-Z0-9\-._~+/]+=*`),
	// Basic auth in authorization headers.
	regexp.MustCompile(`Basic\s+[a-zA-Z0-9+/]+=*`),
	// Generic secret: references (e.g., secret:my-value).
	regexp.MustCompile(`secret:[^\s,}"]+`),
}

// RedactSecrets replaces known secret patterns in a string with [REDACTED].
// This function is safe to call on any string and will not modify non-secret
// content. It applies all patterns from SecretPatterns sequentially.
func RedactSecrets(input string) string {
	result := input
	for _, pattern := range SecretPatterns {
		result = pattern.ReplaceAllString(result, redactPlaceholder)
	}
	return result
}

// RedactHeader redacts the value portion of an authorization-style header.
// If the header name (case-insensitive) is "authorization", "x-api-key",
// "api-key", or "proxy-authorization", the value is replaced entirely.
func RedactHeader(name, value string) string {
	lower := strings.ToLower(name)
	switch lower {
	case "authorization", "proxy-authorization", "x-api-key", "api-key":
		return redactPlaceholder
	default:
		return RedactSecrets(value)
	}
}
