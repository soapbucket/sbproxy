// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	json "github.com/goccy/go-json"
)

func init() {
	Register("prompt_injection", NewInjectionDetector)
}

// InjectionConfig configures prompt injection detection.
type InjectionConfig struct {
	Sensitivity  string   `json:"sensitivity,omitempty"`
	BlockMessage string   `json:"block_message,omitempty"`
	Allowlist    []string `json:"allowlist,omitempty"`
}

type injectionDetector struct {
	config    *InjectionConfig
	patterns  []injectionPattern
	allowlist []*regexp.Regexp
	threshold float64
}

type injectionPattern struct {
	pattern *regexp.Regexp
	weight  float64
	name    string
}

// Precompiled injection detection patterns.
var defaultInjectionPatterns = []injectionPattern{
	// Direct instruction override
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|directives?)`), 0.9, "ignore_previous"},
	{regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)`), 0.9, "disregard_previous"},
	{regexp.MustCompile(`(?i)forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|context)`), 0.85, "forget_previous"},

	// Role hijacking
	{regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an|the)\s+`), 0.7, "role_hijack"},
	{regexp.MustCompile(`(?i)act\s+as\s+(a|an|the|if)\s+`), 0.4, "act_as"},
	{regexp.MustCompile(`(?i)pretend\s+(you'?re?|to\s+be)\s+`), 0.6, "pretend"},
	{regexp.MustCompile(`(?i)switch\s+to\s+.{0,20}\s+mode`), 0.7, "mode_switch"},

	// Jailbreak keywords
	{regexp.MustCompile(`(?i)\b(DAN|do\s+anything\s+now)\b`), 0.8, "dan_jailbreak"},
	{regexp.MustCompile(`(?i)\bjailbreak\b`), 0.7, "jailbreak_keyword"},
	{regexp.MustCompile(`(?i)developer\s+mode\s+(enabled|activated|on)`), 0.8, "dev_mode"},

	// System prompt extraction
	{regexp.MustCompile(`(?i)(reveal|show|display|print|output|repeat)\s+(your\s+)?(system\s+prompt|instructions|initial\s+prompt)`), 0.8, "system_prompt_extract"},
	{regexp.MustCompile(`(?i)what\s+(are|were)\s+your\s+(original\s+)?instructions`), 0.6, "ask_instructions"},

	// Delimiter/boundary attacks
	{regexp.MustCompile(`(?i)\[SYSTEM\]|\[\/INST\]|<\|im_start\|>|<\|system\|>`), 0.9, "delimiter_inject"},
	{regexp.MustCompile(`(?i)###\s*(SYSTEM|INSTRUCTION|NEW\s+INSTRUCTIONS?)`), 0.8, "markdown_inject"},

	// Encoded instructions
	{regexp.MustCompile(`(?i)(base64|rot13|hex)\s*(decode|decrypt|translate)`), 0.5, "encoding_instruct"},

	// Indirect injection - tool/function call manipulation
	{regexp.MustCompile(`(?i)(call|execute|invoke|run)\s+(the\s+)?(function|tool|api|endpoint)\s+`), 0.4, "tool_call_manipulation"},
	{regexp.MustCompile(`(?i)send\s+(the\s+)?(data|results?|output|response)\s+to\s+`), 0.5, "data_exfiltration"},
	{regexp.MustCompile(`(?i)(fetch|get|retrieve|download)\s+.{0,30}(url|http|endpoint|api)`), 0.3, "external_fetch"},
}

// NewInjectionDetector creates a prompt injection detection guardrail.
func NewInjectionDetector(config json.RawMessage) (Guardrail, error) {
	cfg := &InjectionConfig{Sensitivity: "medium"}
	if len(config) > 0 {
		if err := json.Unmarshal(config, cfg); err != nil {
			return nil, err
		}
	}

	var threshold float64
	switch cfg.Sensitivity {
	case "low":
		threshold = 0.8
	case "high":
		threshold = 0.3
	default: // medium
		threshold = 0.5
	}

	var allowlist []*regexp.Regexp
	for _, pattern := range cfg.Allowlist {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist pattern %q: %w", pattern, err)
		}
		allowlist = append(allowlist, re)
	}

	return &injectionDetector{
		config:    cfg,
		patterns:  defaultInjectionPatterns,
		allowlist: allowlist,
		threshold: threshold,
	}, nil
}

// Name performs the name operation on the injectionDetector.
func (d *injectionDetector) Name() string  { return "prompt_injection" }
// Phase performs the phase operation on the injectionDetector.
func (d *injectionDetector) Phase() Phase  { return PhaseInput }

// checkEncodedContent decodes common encodings and checks for injection patterns.
func (d *injectionDetector) checkEncodedContent(text string) (float64, []string) {
	var score float64
	var patterns []string

	// Check for base64-encoded injection attempts
	if b64Score, b64Patterns := d.checkBase64(text); b64Score > 0 {
		score += b64Score
		patterns = append(patterns, b64Patterns...)
	}

	// Check for unicode escape sequences hiding instructions
	if uniScore, uniPatterns := d.checkUnicodeEscapes(text); uniScore > 0 {
		score += uniScore
		patterns = append(patterns, uniPatterns...)
	}

	return score, patterns
}

// checkBase64 looks for base64-encoded segments that decode to injection patterns.
func (d *injectionDetector) checkBase64(text string) (float64, []string) {
	// Find potential base64 segments (at least 20 chars of base64 alphabet)
	b64Re := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	matches := b64Re.FindAllString(text, 5) // Limit to 5 segments

	var score float64
	var patterns []string
	for _, match := range matches {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			// Try URL-safe base64
			decoded, err = base64.URLEncoding.DecodeString(match)
			if err != nil {
				continue
			}
		}
		decodedStr := strings.ToLower(string(decoded))
		for _, kw := range []string{"ignore previous", "system prompt", "you are now", "jailbreak", "disregard"} {
			if strings.Contains(decodedStr, kw) {
				score += 0.8
				patterns = append(patterns, "base64_encoded_injection")
				break
			}
		}
	}
	return score, patterns
}

// checkUnicodeEscapes detects unicode escape sequences that hide injection content.
func (d *injectionDetector) checkUnicodeEscapes(text string) (float64, []string) {
	// Detect sequences of unicode escapes (\uXXXX or &#xXXXX; or &#NNNN;)
	unicodeRe := regexp.MustCompile(`(\\u[0-9a-fA-F]{4}){4,}`)
	htmlEntityRe := regexp.MustCompile(`(&#x?[0-9a-fA-F]+;){4,}`)

	var score float64
	var patterns []string

	if unicodeRe.MatchString(text) {
		score += 0.6
		patterns = append(patterns, "unicode_escape_sequence")
	}
	if htmlEntityRe.MatchString(text) {
		score += 0.6
		patterns = append(patterns, "html_entity_encoding")
	}
	return score, patterns
}

// Check performs the check operation on the injectionDetector.
func (d *injectionDetector) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	// Check allowlist
	for _, re := range d.allowlist {
		if re.MatchString(text) {
			return &Result{Pass: true, Action: ActionAllow}, nil
		}
	}

	var totalScore float64
	var matchedPatterns []string

	for _, p := range d.patterns {
		if p.pattern.MatchString(text) {
			totalScore += p.weight
			matchedPatterns = append(matchedPatterns, p.name)
		}
	}

	// Check for encoded injection attempts
	encodedScore, encodedPatterns := d.checkEncodedContent(text)
	totalScore += encodedScore
	matchedPatterns = append(matchedPatterns, encodedPatterns...)

	// Cap score at 1.0
	if totalScore > 1.0 {
		totalScore = 1.0
	}

	if totalScore >= d.threshold {
		blockMsg := d.config.BlockMessage
		if blockMsg == "" {
			blockMsg = "Potential prompt injection detected"
		}

		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: blockMsg,
			Score:  totalScore,
			Details: map[string]any{
				"patterns":    matchedPatterns,
				"sensitivity": d.config.Sensitivity,
			},
		}, nil
	}

	return &Result{Pass: true, Action: ActionAllow, Score: totalScore}, nil
}

// Transform performs the transform operation on the injectionDetector.
func (d *injectionDetector) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

// ContainsInjectionKeywords is a quick check for obvious injection patterns.
func ContainsInjectionKeywords(text string) bool {
	lower := strings.ToLower(text)
	keywords := []string{
		"ignore previous",
		"disregard previous",
		"forget your instructions",
		"you are now",
		"jailbreak",
		"do anything now",
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
