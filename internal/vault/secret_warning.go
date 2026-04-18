// Copyright 2026 Soap Bucket LLC. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package vault

import (
	"log/slog"
	"regexp"
	"sync"
)

// secretPatterns contains compiled patterns for known secret formats that
// should not appear as plaintext in configuration files.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^sk-[a-zA-Z0-9]{20,}`),      // OpenAI API keys
	regexp.MustCompile(`^ghp_[a-zA-Z0-9]{36,}`),      // GitHub personal access tokens
	regexp.MustCompile(`^AKIA[A-Z0-9]{16}`),           // AWS access key IDs
	regexp.MustCompile(`^xoxb-[0-9]+-[a-zA-Z0-9]+`),  // Slack bot tokens
	regexp.MustCompile(`^glpat-[a-zA-Z0-9\-_]{20,}`), // GitLab personal access tokens
	regexp.MustCompile(`^shpat_[a-fA-F0-9]{32}`),     // Shopify private app tokens
	regexp.MustCompile(`^SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}`), // SendGrid API keys
	regexp.MustCompile(`^rk_live_[a-zA-Z0-9]{24,}`),  // Stripe restricted keys
	regexp.MustCompile(`^sk_live_[a-zA-Z0-9]{24,}`),  // Stripe secret keys
}

// SecretWarner checks config field values and warns if they look like
// unvaulted secrets (e.g., a raw API key instead of a vault reference).
// It tracks which fields have already been warned about to avoid log spam.
type SecretWarner struct {
	mu     sync.Mutex
	warned map[string]bool
}

// NewSecretWarner creates a new SecretWarner.
func NewSecretWarner() *SecretWarner {
	return &SecretWarner{
		warned: make(map[string]bool),
	}
}

// CheckAndWarn logs a warning if the value looks like an unvaulted secret.
// Returns true if a warning was issued. Each field is warned about at most
// once per SecretWarner instance.
func (sw *SecretWarner) CheckAndWarn(fieldName, value string) bool {
	if value == "" {
		return false
	}

	// Skip values that are already vault references or templates
	if isSecretReference(value) {
		return false
	}

	for _, pattern := range secretPatterns {
		if pattern.MatchString(value) {
			sw.mu.Lock()
			if sw.warned[fieldName] {
				sw.mu.Unlock()
				return false
			}
			sw.warned[fieldName] = true
			sw.mu.Unlock()

			slog.Warn("config field contains what appears to be an unvaulted secret - use a vault reference or encrypted value instead",
				"field", fieldName,
				"pattern_hint", patternHint(value),
			)
			return true
		}
	}

	return false
}

// Reset clears all tracked warnings, allowing fields to be warned about again.
func (sw *SecretWarner) Reset() {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.warned = make(map[string]bool)
}

// isSecretReference returns true if the value looks like a vault reference,
// template, or env var - patterns that indicate the value is already properly
// managed.
func isSecretReference(value string) bool {
	// Already a vault/secret reference
	if len(value) > 6 && value[:6] == "vault:" {
		return true
	}
	if len(value) > 7 && value[:7] == "secret:" {
		return true
	}
	// Template syntax
	if len(value) > 4 && value[:2] == "{{" {
		return true
	}
	// Env var reference
	if len(value) > 3 && value[:2] == "${" {
		return true
	}
	// File reference
	if len(value) > 5 && value[:5] == "file:" {
		return true
	}
	return false
}

// patternHint returns a redacted hint about what type of secret was detected,
// showing only the prefix (first few characters) for identification.
func patternHint(value string) string {
	if len(value) < 4 {
		return "***"
	}
	// Show just enough prefix for identification
	prefixLen := 4
	if len(value) > 8 {
		prefixLen = 6
	}
	return value[:prefixLen] + "***"
}
