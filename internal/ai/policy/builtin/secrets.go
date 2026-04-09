package builtin

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// SecretDetector detects leaked secrets, API keys, and high-entropy strings in content.
// Detects: AWS keys, GitHub tokens, Stripe keys, generic API keys, high Shannon entropy.
// Config fields:
//   - "types" ([]string) - optional filter for which secret types to detect
//   - "entropy_threshold" (float64) - Shannon entropy threshold (default: 4.5)
//   - "entropy_min_length" (int) - minimum token length for entropy check (default: 20)
type SecretDetector struct{}

// secretPattern holds a secret type name and its regex.
type secretPattern struct {
	name    string
	pattern *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"aws_access_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"aws_secret_key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`)},
	{"github_token", regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b`)},
	{"github_fine_grained", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}\b`)},
	{"stripe_key", regexp.MustCompile(`\b(sk|pk)_(test|live)_[A-Za-z0-9]{20,99}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,250}\b`)},
	{"generic_api_key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,64}['"]?`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[A-Za-z0-9_\-]{35}\b`)},
	{"heroku_api_key", regexp.MustCompile(`(?i)heroku.*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)},
}

// Detect checks content for leaked secrets and high-entropy strings.
func (d *SecretDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	types, _ := toStringSlice(config.Config["types"])
	entropyThreshold := 4.5
	if et, ok := toFloat64(config.Config["entropy_threshold"]); ok {
		entropyThreshold = et
	}
	entropyMinLen := 20
	if eml, ok := toInt(config.Config["entropy_min_length"]); ok {
		entropyMinLen = eml
	}

	typeSet := make(map[string]bool, len(types))
	for _, t := range types {
		typeSet[strings.ToLower(t)] = true
	}
	checkAll := len(types) == 0

	var found []string

	// Check known patterns.
	for _, sp := range secretPatterns {
		if !checkAll && !typeSet[sp.name] {
			continue
		}
		if sp.pattern.MatchString(content) {
			found = append(found, sp.name)
		}
	}

	// Check for high-entropy strings.
	if checkAll || typeSet["high_entropy"] {
		words := strings.Fields(content)
		for _, word := range words {
			if len(word) >= entropyMinLen {
				entropy := shannonEntropy(word)
				if entropy >= entropyThreshold {
					found = append(found, "high_entropy")
					break
				}
			}
		}
	}

	if len(found) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("detected secrets: %s", strings.Join(found, ", "))
	}

	result.Latency = time.Since(start)
	return result, nil
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
