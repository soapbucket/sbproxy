// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"strings"
	"unicode/utf8"
)

func init() {
	Register("max_tokens", NewMaxTokensGuard)
	Register("length_limit", NewLengthLimitGuard)
}

// MaxTokensConfig configures maximum token limits.
type MaxTokensConfig struct {
	MaxTokens int `json:"max_tokens"`
}

type maxTokensGuard struct {
	maxTokens int
}

// NewMaxTokensGuard creates a token limit guardrail.
func NewMaxTokensGuard(config json.RawMessage) (Guardrail, error) {
	cfg := &MaxTokensConfig{MaxTokens: 16000}
	if len(config) > 0 {
		if err := json.Unmarshal(config, cfg); err != nil {
			return nil, err
		}
	}
	return &maxTokensGuard{maxTokens: cfg.MaxTokens}, nil
}

// Name performs the name operation on the maxTokensGuard.
func (g *maxTokensGuard) Name() string { return "max_tokens" }

// Phase performs the phase operation on the maxTokensGuard.
func (g *maxTokensGuard) Phase() Phase { return PhaseInput }

// Check performs the check operation on the maxTokensGuard.
func (g *maxTokensGuard) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	// Estimate tokens as chars/4
	estimated := (len(text) + 3) / 4
	if estimated > g.maxTokens {
		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: fmt.Sprintf("Input exceeds token limit: ~%d tokens (max: %d)", estimated, g.maxTokens),
			Details: map[string]any{
				"estimated_tokens": estimated,
				"max_tokens":       g.maxTokens,
			},
		}, nil
	}
	return &Result{Pass: true, Action: ActionAllow}, nil
}

// Transform performs the transform operation on the maxTokensGuard.
func (g *maxTokensGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

// LengthLimitConfig configures minimum/maximum word and character limits.
type LengthLimitConfig struct {
	MinWords int `json:"min_words,omitempty"`
	MaxWords int `json:"max_words,omitempty"`
	MinChars int `json:"min_chars,omitempty"`
	MaxChars int `json:"max_chars,omitempty"`
}

type lengthLimitGuard struct {
	cfg LengthLimitConfig
}

// NewLengthLimitGuard creates a text length guardrail.
func NewLengthLimitGuard(config json.RawMessage) (Guardrail, error) {
	cfg := LengthLimitConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}
	return &lengthLimitGuard{cfg: cfg}, nil
}

// Name performs the name operation on the lengthLimitGuard.
func (g *lengthLimitGuard) Name() string { return "length_limit" }

// Phase performs the phase operation on the lengthLimitGuard.
func (g *lengthLimitGuard) Phase() Phase { return PhaseInput }

// Check performs the check operation on the lengthLimitGuard.
func (g *lengthLimitGuard) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	wordCount := len(strings.Fields(text))
	charCount := utf8.RuneCountInString(text)

	details := map[string]any{
		"words": wordCount,
		"chars": charCount,
	}
	if g.cfg.MinWords > 0 {
		details["min_words"] = g.cfg.MinWords
	}
	if g.cfg.MaxWords > 0 {
		details["max_words"] = g.cfg.MaxWords
	}
	if g.cfg.MinChars > 0 {
		details["min_chars"] = g.cfg.MinChars
	}
	if g.cfg.MaxChars > 0 {
		details["max_chars"] = g.cfg.MaxChars
	}

	switch {
	case g.cfg.MinWords > 0 && wordCount < g.cfg.MinWords:
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  fmt.Sprintf("Input has too few words: %d (min: %d)", wordCount, g.cfg.MinWords),
			Details: details,
		}, nil
	case g.cfg.MaxWords > 0 && wordCount > g.cfg.MaxWords:
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  fmt.Sprintf("Input exceeds max words: %d (max: %d)", wordCount, g.cfg.MaxWords),
			Details: details,
		}, nil
	case g.cfg.MinChars > 0 && charCount < g.cfg.MinChars:
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  fmt.Sprintf("Input has too few characters: %d (min: %d)", charCount, g.cfg.MinChars),
			Details: details,
		}, nil
	case g.cfg.MaxChars > 0 && charCount > g.cfg.MaxChars:
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  fmt.Sprintf("Input exceeds max characters: %d (max: %d)", charCount, g.cfg.MaxChars),
			Details: details,
		}, nil
	default:
		return &Result{Pass: true, Action: ActionAllow}, nil
	}
}

// Transform performs the transform operation on the lengthLimitGuard.
func (g *lengthLimitGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}
