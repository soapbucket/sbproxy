// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"regexp"
	"strings"
)

func init() {
	Register("regex_guard", NewRegexGuard)
}

// RegexConfig configures regex-based content filtering.
type RegexConfig struct {
	Deny  []string `json:"deny,omitempty"`
	Allow []string `json:"allow,omitempty"`
}

type regexGuard struct {
	deny  []*regexp.Regexp
	allow []*regexp.Regexp
}

// NewRegexGuard creates a regex-based guardrail.
func NewRegexGuard(config json.RawMessage) (Guardrail, error) {
	cfg := &RegexConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, cfg); err != nil {
			return nil, err
		}
	}

	g := &regexGuard{}

	for _, pattern := range cfg.Deny {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid deny pattern %q: %w", pattern, err)
		}
		g.deny = append(g.deny, re)
	}

	for _, pattern := range cfg.Allow {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid allow pattern %q: %w", pattern, err)
		}
		g.allow = append(g.allow, re)
	}

	return g, nil
}

// Name performs the name operation on the regexGuard.
func (g *regexGuard) Name() string { return "regex_guard" }

// Phase performs the phase operation on the regexGuard.
func (g *regexGuard) Phase() Phase { return PhaseInput }

// Check performs the check operation on the regexGuard.
func (g *regexGuard) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	// Check allow patterns first — if any match, allow
	for _, re := range g.allow {
		if re.MatchString(text) {
			return &Result{Pass: true, Action: ActionAllow}, nil
		}
	}

	// Check deny patterns
	var matched []string
	for _, re := range g.deny {
		if re.MatchString(text) {
			matched = append(matched, re.String())
		}
	}

	if len(matched) > 0 {
		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: "Content matched deny pattern: " + strings.Join(matched, ", "),
			Details: map[string]any{
				"matched_patterns": matched,
			},
		}, nil
	}

	return &Result{Pass: true, Action: ActionAllow}, nil
}

// Transform performs the transform operation on the regexGuard.
func (g *regexGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}
