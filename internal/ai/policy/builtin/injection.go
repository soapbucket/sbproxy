package builtin

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// InjectionDetector detects prompt injection attempts in content.
// Detects patterns like "ignore previous instructions", "system prompt extraction",
// role impersonation, and other common injection techniques.
// Config fields:
//   - "sensitivity" (string) - "low", "medium" (default), "high"
//   - "extra_patterns" ([]string) - additional regex patterns to check
type InjectionDetector struct{}

// injectionPattern represents a prompt injection pattern with severity.
type injectionPattern struct {
	name     string
	pattern  *regexp.Regexp
	severity string // "low", "medium", "high"
}

var injectionPatterns = []injectionPattern{
	// Instruction override attempts.
	{"ignore_instructions", regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier|original)\s+(instructions?|prompts?|rules?|guidelines?|directions?)`), "medium"},
	{"new_instructions", regexp.MustCompile(`(?i)\bnew\s+(instructions?|rules?|guidelines?)\s*:`), "medium"},

	// System prompt extraction.
	{"system_prompt_extract", regexp.MustCompile(`(?i)(show|reveal|display|print|output|repeat|tell me)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?|initial\s+prompt)`), "high"},
	{"repeat_above", regexp.MustCompile(`(?i)(repeat|print|show)\s+(everything|all|text)\s+(above|before|prior)`), "high"},

	// Role impersonation.
	{"role_play", regexp.MustCompile(`(?i)you\s+are\s+now\s+(a |an )?(?:DAN|jailbroken|unrestricted|unfiltered)`), "high"},
	{"act_as", regexp.MustCompile(`(?i)(act|pretend|behave)\s+(as|like)\s+(a |an )?(different|new|unrestricted|unfiltered)\s+(ai|assistant|model|system)`), "high"},

	// Delimiter injection.
	{"delimiter_injection", regexp.MustCompile("(?i)(" + "```" + "|<\\|im_start\\||<\\|system\\||<\\|endoftext\\||<\\|im_end\\|)"), "medium"},
	{"xml_injection", regexp.MustCompile(`(?i)<\s*(system|assistant|user|instruction)\s*>`), "medium"},

	// Encoding tricks.
	{"base64_instruction", regexp.MustCompile(`(?i)(decode|base64|rot13|hex)\s+(this|the following|and follow)`), "low"},

	// Output manipulation.
	{"output_format", regexp.MustCompile(`(?i)(respond|answer|reply)\s+(only|exclusively)\s+(in|with)\s+(json|xml|code|yes|no)`), "low"},
}

// Detect checks content for prompt injection patterns.
func (d *InjectionDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	sensitivity, _ := toString(config.Config["sensitivity"])
	if sensitivity == "" {
		sensitivity = "medium"
	}

	extraPatterns, _ := toStringSlice(config.Config["extra_patterns"])

	minSeverity := severityLevel(sensitivity)

	var matched []string
	for _, ip := range injectionPatterns {
		if severityLevel(ip.severity) < minSeverity {
			continue
		}
		if ip.pattern.MatchString(content) {
			matched = append(matched, ip.name)
		}
	}

	// Check extra patterns.
	for _, pattern := range extraPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(content) {
			matched = append(matched, "custom_pattern")
		}
	}

	if len(matched) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("injection patterns detected: %s", strings.Join(matched, ", "))
	}

	result.Latency = time.Since(start)
	return result, nil
}

// severityLevel converts severity string to numeric level.
func severityLevel(s string) int {
	switch strings.ToLower(s) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 2
	}
}
