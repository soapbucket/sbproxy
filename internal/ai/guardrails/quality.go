// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"math"
	"strings"
	"unicode"
)

func init() {
	Register("quality", NewQualityGuardrail)
}

// QualityConfig configures quality detection.
type QualityConfig struct {
	MinLength          int     `json:"min_length,omitempty"`
	MaxRepetitionRatio float64 `json:"max_repetition_ratio,omitempty"`
	MinEntropyScore    float64 `json:"min_entropy_score,omitempty"`
}

// QualityGuardrail detects low-quality AI output.
type QualityGuardrail struct {
	config QualityConfig
}

// NewQualityGuardrail creates a quality detection guardrail.
func NewQualityGuardrail(config json.RawMessage) (Guardrail, error) {
	cfg := QualityConfig{
		MaxRepetitionRatio: 0.5,
		MinEntropyScore:    0.3,
	}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}
	if cfg.MaxRepetitionRatio <= 0 || cfg.MaxRepetitionRatio > 1.0 {
		cfg.MaxRepetitionRatio = 0.5
	}
	if cfg.MinEntropyScore <= 0 || cfg.MinEntropyScore > 1.0 {
		cfg.MinEntropyScore = 0.3
	}

	return &QualityGuardrail{config: cfg}, nil
}

// Name returns the guardrail identifier.
func (g *QualityGuardrail) Name() string { return "quality" }

// Phase returns when this guardrail runs.
func (g *QualityGuardrail) Phase() Phase { return PhaseOutput }

// Check evaluates content for quality issues.
func (g *QualityGuardrail) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	var issues []string

	// Check minimum length
	if g.config.MinLength > 0 && len(text) < g.config.MinLength {
		issues = append(issues, fmt.Sprintf("response too short: %d chars (min %d)", len(text), g.config.MinLength))
	}

	// Check word repetition ratio
	repetitionRatio := wordRepetitionRatio(text)
	if repetitionRatio > g.config.MaxRepetitionRatio {
		issues = append(issues, fmt.Sprintf("high word repetition ratio: %.2f (max %.2f)", repetitionRatio, g.config.MaxRepetitionRatio))
	}

	// Check character entropy
	entropy := characterEntropy(text)
	if entropy < g.config.MinEntropyScore {
		issues = append(issues, fmt.Sprintf("low character entropy: %.2f (min %.2f)", entropy, g.config.MinEntropyScore))
	}

	if len(issues) > 0 {
		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: "Quality check failed: " + strings.Join(issues, "; "),
			Score:  entropy,
			Details: map[string]any{
				"issues":           issues,
				"repetition_ratio": repetitionRatio,
				"entropy":          entropy,
				"length":           len(text),
			},
		}, nil
	}

	return &Result{Pass: true, Action: ActionAllow, Score: entropy}, nil
}

// Transform is a no-op for quality detection.
func (g *QualityGuardrail) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

// wordRepetitionRatio calculates the ratio of repeated words to total words.
// A value of 0.0 means all words are unique; 1.0 means maximum repetition.
func wordRepetitionRatio(text string) float64 {
	words := strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	if len(words) <= 1 {
		return 0
	}

	unique := make(map[string]bool, len(words))
	for _, w := range words {
		unique[strings.ToLower(w)] = true
	}

	// Ratio of repeated words: 1 - (unique/total)
	return 1.0 - float64(len(unique))/float64(len(words))
}

// characterEntropy calculates the normalized Shannon entropy of text.
// Returns a value between 0.0 (single repeated character) and 1.0 (uniform distribution).
func characterEntropy(text string) float64 {
	if len(text) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	total := 0
	for _, r := range text {
		freq[r]++
		total++
	}

	if total == 0 || len(freq) == 1 {
		return 0
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	// Normalize by max possible entropy (log2 of unique chars count)
	maxEntropy := math.Log2(float64(len(freq)))
	if maxEntropy == 0 {
		return 0
	}

	normalized := entropy / maxEntropy
	if normalized > 1.0 {
		normalized = 1.0
	}
	return normalized
}
