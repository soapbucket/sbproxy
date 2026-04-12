// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"strings"
	"unicode"
)

func init() {
	Register("sentiment", NewSentimentGuard)
}

// SentimentConfig configures lexicon-based sentiment scoring thresholds.
type SentimentConfig struct {
	MinScore float64 `json:"min_score,omitempty"`
	MaxScore float64 `json:"max_score,omitempty"`
}

type sentimentGuard struct {
	minScore float64
	maxScore float64
}

var positiveLexicon = map[string]bool{
	"good": true, "great": true, "excellent": true, "helpful": true, "clear": true, "safe": true,
	"happy": true, "love": true, "kind": true, "friendly": true, "positive": true, "success": true,
	"improve": true, "benefit": true, "thanks": true, "appreciate": true, "awesome": true, "amazing": true,
}

var negativeLexicon = map[string]bool{
	"bad": true, "awful": true, "terrible": true, "hate": true, "angry": true, "stupid": true,
	"idiot": true, "worthless": true, "horrible": true, "useless": true, "failure": true, "disgusting": true,
	"violent": true, "threat": true, "abuse": true, "toxic": true, "harm": true, "dangerous": true,
}

// NewSentimentGuard creates and initializes a new SentimentGuard.
func NewSentimentGuard(config json.RawMessage) (Guardrail, error) {
	cfg := SentimentConfig{MinScore: -1, MaxScore: 1}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}
	return &sentimentGuard{minScore: cfg.MinScore, maxScore: cfg.MaxScore}, nil
}

// Name performs the name operation on the sentimentGuard.
func (g *sentimentGuard) Name() string { return "sentiment" }
// Phase performs the phase operation on the sentimentGuard.
func (g *sentimentGuard) Phase() Phase { return PhaseOutput }

// Check performs the check operation on the sentimentGuard.
func (g *sentimentGuard) Check(_ context.Context, content *Content) (*Result, error) {
	words := sentimentWords(content.ExtractText())
	if len(words) == 0 {
		return &Result{Pass: true, Action: ActionAllow, Score: 0}, nil
	}
	pos := 0
	neg := 0
	for _, w := range words {
		if positiveLexicon[w] {
			pos++
		}
		if negativeLexicon[w] {
			neg++
		}
	}
	score := float64(pos-neg) / float64(len(words))
	details := map[string]any{
		"positive_count": pos,
		"negative_count": neg,
		"word_count":     len(words),
	}

	if score < g.minScore {
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  fmt.Sprintf("Sentiment score %.3f is below minimum %.3f", score, g.minScore),
			Score:   score,
			Details: details,
		}, nil
	}
	if score > g.maxScore {
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  fmt.Sprintf("Sentiment score %.3f is above maximum %.3f", score, g.maxScore),
			Score:   score,
			Details: details,
		}, nil
	}
	return &Result{Pass: true, Action: ActionAllow, Score: score, Details: details}, nil
}

// Transform performs the transform operation on the sentimentGuard.
func (g *sentimentGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

func sentimentWords(s string) []string {
	fields := strings.Fields(strings.ToLower(s))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		var b strings.Builder
		for _, r := range f {
			if unicode.IsLetter(r) {
				b.WriteRune(r)
			}
		}
		w := b.String()
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}
