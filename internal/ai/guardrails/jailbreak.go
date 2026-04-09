// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"regexp"
)

func init() {
	Register("jailbreak", NewJailbreakGuardrail)
}

// JailbreakConfig configures jailbreak detection.
type JailbreakConfig struct {
	Threshold      float64  `json:"threshold,omitempty"`
	CustomPatterns []string `json:"custom_patterns,omitempty"`
}

type jailbreakPattern struct {
	pattern  *regexp.Regexp
	severity float64
	name     string
}

// JailbreakGuardrail detects common jailbreak patterns in input.
type JailbreakGuardrail struct {
	config   JailbreakConfig
	patterns []jailbreakPattern
}

// Precompiled jailbreak detection patterns.
var defaultJailbreakPatterns = []jailbreakPattern{
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`), 0.9, "ignore_previous"},
	{regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+`), 0.6, "roleplay_exploit"},
	{regexp.MustCompile(`(?i)do\s+anything\s+now`), 0.9, "dan_prompt"},
	{regexp.MustCompile(`(?i)jailbreak`), 0.7, "jailbreak_keyword"},
	{regexp.MustCompile(`(?i)you\s+are\s+now\s+(in\s+)?developer\s+mode`), 0.85, "developer_mode"},
	{regexp.MustCompile(`(?i)repeat\s+(your|the)\s+(system\s+)?prompt`), 0.8, "prompt_extraction"},
	{regexp.MustCompile(`(?i)what\s+are\s+your\s+(initial\s+)?instructions`), 0.7, "instruction_extraction"},
	{regexp.MustCompile(`(?i)bypass\s+(your\s+)?(safety|content)\s+(filter|guardrail|restriction)`), 0.9, "bypass_safety"},
	{regexp.MustCompile(`(?i)in\s+a\s+hypothetical\s+(world|scenario)\s+where`), 0.5, "hypothetical_framing"},
	{regexp.MustCompile(`(?i)act\s+as\s+(if|though)\s+you\s+(have\s+)?no\s+(restrictions|rules|guidelines)`), 0.85, "no_restrictions"},
}

// NewJailbreakGuardrail creates a jailbreak detection guardrail.
func NewJailbreakGuardrail(config json.RawMessage) (Guardrail, error) {
	cfg := JailbreakConfig{Threshold: 0.8}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}
	if cfg.Threshold <= 0 || cfg.Threshold > 1.0 {
		cfg.Threshold = 0.8
	}

	patterns := make([]jailbreakPattern, len(defaultJailbreakPatterns))
	copy(patterns, defaultJailbreakPatterns)

	for _, p := range cfg.CustomPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid custom jailbreak pattern %q: %w", p, err)
		}
		patterns = append(patterns, jailbreakPattern{
			pattern:  re,
			severity: 0.7,
			name:     "custom",
		})
	}

	return &JailbreakGuardrail{config: cfg, patterns: patterns}, nil
}

// Name returns the guardrail identifier.
func (g *JailbreakGuardrail) Name() string { return "jailbreak" }

// Phase returns when this guardrail runs.
func (g *JailbreakGuardrail) Phase() Phase { return PhaseInput }

// Check evaluates content for jailbreak patterns.
func (g *JailbreakGuardrail) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	var totalScore float64
	var matchedPatterns []string

	for _, p := range g.patterns {
		if p.pattern.MatchString(text) {
			totalScore += p.severity
			matchedPatterns = append(matchedPatterns, p.name)
		}
	}

	if totalScore > 1.0 {
		totalScore = 1.0
	}

	if totalScore >= g.config.Threshold {
		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: "Jailbreak attempt detected",
			Score:  totalScore,
			Details: map[string]any{
				"patterns":  matchedPatterns,
				"threshold": g.config.Threshold,
			},
		}, nil
	}

	return &Result{Pass: true, Action: ActionAllow, Score: totalScore}, nil
}

// Transform is a no-op for jailbreak detection.
func (g *JailbreakGuardrail) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}
