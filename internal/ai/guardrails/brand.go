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
	Register("brand_mention", NewBrandMentionGuard)
}

// BrandMentionConfig configures competitor and brand mention filtering.
type BrandMentionConfig struct {
	BlockBrands   []string `json:"block_brands,omitempty"`
	AllowBrands   []string `json:"allow_brands,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
	WordBoundary  *bool    `json:"word_boundary,omitempty"`
}

type brandMentionGuard struct {
	caseSensitive bool
	blockRegexes  []brandPattern
}

type brandPattern struct {
	brand string
	re    *regexp.Regexp
}

// NewBrandMentionGuard creates and initializes a new BrandMentionGuard.
func NewBrandMentionGuard(config json.RawMessage) (Guardrail, error) {
	cfg := BrandMentionConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}
	wordBoundary := true
	if cfg.WordBoundary != nil {
		wordBoundary = *cfg.WordBoundary
	}

	allowSet := map[string]bool{}
	for _, b := range cfg.AllowBrands {
		key := b
		if !cfg.CaseSensitive {
			key = strings.ToLower(key)
		}
		allowSet[key] = true
	}

	var compiled []brandPattern
	for _, b := range cfg.BlockBrands {
		key := b
		if !cfg.CaseSensitive {
			key = strings.ToLower(key)
		}
		if allowSet[key] {
			continue
		}
		pat := regexp.QuoteMeta(b)
		if wordBoundary {
			pat = `\b` + pat + `\b`
		}
		if !cfg.CaseSensitive {
			pat = `(?i)` + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("brand_mention: invalid brand %q: %w", b, err)
		}
		compiled = append(compiled, brandPattern{brand: b, re: re})
	}
	return &brandMentionGuard{
		caseSensitive: cfg.CaseSensitive,
		blockRegexes:  compiled,
	}, nil
}

// Name performs the name operation on the brandMentionGuard.
func (g *brandMentionGuard) Name() string { return "brand_mention" }
// Phase performs the phase operation on the brandMentionGuard.
func (g *brandMentionGuard) Phase() Phase { return PhaseOutput }

// Check performs the check operation on the brandMentionGuard.
func (g *brandMentionGuard) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}
	matched := make([]string, 0)
	for _, p := range g.blockRegexes {
		if p.re.MatchString(text) {
			matched = append(matched, p.brand)
		}
	}
	if len(matched) > 0 {
		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: "Blocked brand mention detected",
			Details: map[string]any{
				"matched_brands": matched,
			},
		}, nil
	}
	return &Result{Pass: true, Action: ActionAllow}, nil
}

// Transform performs the transform operation on the brandMentionGuard.
func (g *brandMentionGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}
