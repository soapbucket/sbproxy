// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"strings"

	json "github.com/goccy/go-json"
)

func init() {
	Register("competitor_block", NewCompetitorBlockGuard)
}

// CompetitorBlockConfig configures competitor mention blocking.
type CompetitorBlockConfig struct {
	Competitors []string `json:"competitors" yaml:"competitors"`
	Action      string   `json:"action,omitempty" yaml:"action"`   // "block" or "flag"
	Message     string   `json:"message,omitempty" yaml:"message"` // custom rejection message
}

type competitorBlockGuard struct {
	competitors []string // normalized to lowercase
	action      Action
	message     string
}

// NewCompetitorBlockGuard creates a guardrail that blocks or flags content mentioning competitors.
func NewCompetitorBlockGuard(config json.RawMessage) (Guardrail, error) {
	cfg := CompetitorBlockConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}

	action := ActionBlock
	if cfg.Action == "flag" {
		action = ActionFlag
	}

	competitors := make([]string, len(cfg.Competitors))
	for i, c := range cfg.Competitors {
		competitors[i] = strings.ToLower(c)
	}

	msg := cfg.Message
	if msg == "" {
		msg = "Content mentions a competitor"
	}

	return &competitorBlockGuard{
		competitors: competitors,
		action:      action,
		message:     msg,
	}, nil
}

// Name returns the guardrail identifier.
func (g *competitorBlockGuard) Name() string { return "competitor_block" }

// Phase returns when this guardrail runs.
func (g *competitorBlockGuard) Phase() Phase { return PhaseOutput }

// Check scans content for competitor mentions.
func (g *competitorBlockGuard) Check(_ context.Context, content *Content) (*Result, error) {
	text := strings.ToLower(content.ExtractText())
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow, Guardrail: "competitor_block"}, nil
	}

	var matched []string
	for _, comp := range g.competitors {
		if strings.Contains(text, comp) {
			matched = append(matched, comp)
		}
	}

	if len(matched) > 0 {
		return &Result{
			Guardrail: "competitor_block",
			Pass:      false,
			Action:    g.action,
			Reason:    g.message,
			Details: map[string]any{
				"matched_competitors": matched,
			},
		}, nil
	}

	return &Result{Pass: true, Action: ActionAllow, Guardrail: "competitor_block"}, nil
}

// Transform is a no-op for competitor blocking.
func (g *competitorBlockGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

// CheckCompetitorBlock scans input text for competitor mentions using the provided config.
// Returns whether the content is blocked and which competitor matched first.
func CheckCompetitorBlock(input string, cfg CompetitorBlockConfig) (blocked bool, matchedCompetitor string) {
	lower := strings.ToLower(input)
	for _, comp := range cfg.Competitors {
		if strings.Contains(lower, strings.ToLower(comp)) {
			return true, comp
		}
	}
	return false, ""
}
