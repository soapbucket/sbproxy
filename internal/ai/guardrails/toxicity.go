// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	json "github.com/goccy/go-json"
	"regexp"
	"strings"
)

func init() {
	Register("toxicity", NewToxicityFilter)
}

// ToxicityConfig configures toxicity detection.
type ToxicityConfig struct {
	Threshold          float64            `json:"threshold,omitempty"`
	Categories         []string           `json:"categories,omitempty"`
	CategoryThresholds map[string]float64 `json:"category_thresholds,omitempty"` // Per-category thresholds
	ContextAware       bool               `json:"context_aware,omitempty"`       // Skip medical/legal false positives
}

type toxicityFilter struct {
	threshold          float64
	patterns           []toxicityPattern
	categoryThresholds map[string]float64
	contextAware       bool
}

type toxicityPattern struct {
	pattern  *regexp.Regexp
	weight   float64
	category string
}

var contextAwarePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(medical|clinical|diagnosis|patient|treatment|symptom|therapy)\b`),
	regexp.MustCompile(`(?i)\b(legal|court|statute|attorney|defendant|plaintiff|prosecution)\b`),
	regexp.MustCompile(`(?i)\b(academic|research|study|analysis|historical|documentary)\b`),
}

// severity returns the severity level based on score.
func severity(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

// Default toxicity patterns with scoring weights.
var defaultToxicityPatterns = []toxicityPattern{
	// Hate speech indicators
	{regexp.MustCompile(`(?i)\b(hate|hatred|despise)\s+(all|every)\s+`), 0.8, "hate_speech"},
	{regexp.MustCompile(`(?i)\b(kill|murder|eliminate)\s+(all|every|them)\b`), 0.9, "violence"},

	// Threats
	{regexp.MustCompile(`(?i)\bi('ll|'m going to|\s+will)\s+(kill|hurt|destroy|attack)\b`), 0.9, "threat"},
	{regexp.MustCompile(`(?i)\b(threat|threaten|threatening)\b`), 0.4, "threat"},

	// Harassment
	{regexp.MustCompile(`(?i)\b(you'?re?\s+)?(worthless|pathetic|disgusting|stupid|idiot|moron)\b`), 0.5, "harassment"},

	// Self-harm
	{regexp.MustCompile(`(?i)\b(how\s+to\s+)?(commit\s+suicide|kill\s+(my|your)self|end\s+(my|your)\s+life)\b`), 0.95, "self_harm"},

	// Illegal activities
	{regexp.MustCompile(`(?i)\bhow\s+to\s+(make|build|create)\s+(a\s+)?(bomb|weapon|explosive)\b`), 0.9, "illegal"},
	{regexp.MustCompile(`(?i)\bhow\s+to\s+(hack|crack|break\s+into)\b`), 0.6, "illegal"},
}

// NewToxicityFilter creates a toxicity detection guardrail.
func NewToxicityFilter(config json.RawMessage) (Guardrail, error) {
	cfg := &ToxicityConfig{Threshold: 0.7}
	if len(config) > 0 {
		if err := json.Unmarshal(config, cfg); err != nil {
			return nil, err
		}
	}

	patterns := defaultToxicityPatterns
	if len(cfg.Categories) > 0 {
		catSet := make(map[string]bool, len(cfg.Categories))
		for _, c := range cfg.Categories {
			catSet[c] = true
		}
		var filtered []toxicityPattern
		for _, p := range patterns {
			if catSet[p.category] {
				filtered = append(filtered, p)
			}
		}
		patterns = filtered
	}

	return &toxicityFilter{
		threshold:          cfg.Threshold,
		patterns:           patterns,
		categoryThresholds: cfg.CategoryThresholds,
		contextAware:       cfg.ContextAware,
	}, nil
}

// Name performs the name operation on the toxicityFilter.
func (f *toxicityFilter) Name() string  { return "toxicity" }
// Phase performs the phase operation on the toxicityFilter.
func (f *toxicityFilter) Phase() Phase  { return PhaseOutput }

// Check performs the check operation on the toxicityFilter.
func (f *toxicityFilter) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	// Context-aware: reduce sensitivity for medical/legal/academic content
	contextMultiplier := 1.0
	if f.contextAware {
		for _, re := range contextAwarePatterns {
			if re.MatchString(text) {
				contextMultiplier = 1.5 // Raise effective threshold
				break
			}
		}
	}

	var maxScore float64
	categories := map[string]float64{}

	for _, p := range f.patterns {
		if p.pattern.MatchString(text) {
			if p.weight > maxScore {
				maxScore = p.weight
			}
			if existing, ok := categories[p.category]; !ok || p.weight > existing {
				categories[p.category] = p.weight
			}
		}
	}

	// Check per-category thresholds
	var triggered []string
	for cat, score := range categories {
		threshold := f.threshold * contextMultiplier
		if catThreshold, ok := f.categoryThresholds[cat]; ok {
			threshold = catThreshold * contextMultiplier
		}
		if score >= threshold {
			triggered = append(triggered, cat)
		}
	}

	// Build category scores for details
	categoryScores := make(map[string]float64, len(categories))
	for cat, score := range categories {
		categoryScores[cat] = score
	}

	if len(triggered) > 0 {
		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: "Toxic content detected: " + strings.Join(triggered, ", "),
			Score:  maxScore,
			Details: map[string]any{
				"categories":      triggered,
				"category_scores": categoryScores,
				"severity":        severity(maxScore),
				"max_score":       maxScore,
			},
		}, nil
	}

	return &Result{Pass: true, Action: ActionAllow, Score: maxScore}, nil
}

// Transform performs the transform operation on the toxicityFilter.
func (f *toxicityFilter) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}
