// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"fmt"
	"log/slog"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/request/classifier"
)

func init() {
	Register("local_classify", NewLocalClassifyGuardrail)
}

// LocalClassifyConfig configures the local classification guardrail.
type LocalClassifyConfig struct {
	BlockLabels        []string                     `json:"block_labels,omitempty"`
	BlockThreshold     float64                      `json:"block_threshold,omitempty"`
	SafeLabels         []string                     `json:"safe_labels,omitempty"`
	SafeThreshold      float64                      `json:"safe_threshold,omitempty"`
	SafeSkipGuardrails []string                     `json:"safe_skip_guardrails,omitempty"`
	Labels             []LocalClassifyLabel         `json:"labels,omitempty"`
	Classification     *LocalClassifyClassification `json:"classification,omitempty"`
}

// LocalClassifyLabel defines a classification label with patterns.
type LocalClassifyLabel struct {
	Name     string   `json:"name"`
	Weight   float64  `json:"weight,omitempty"`
	Patterns []string `json:"patterns"`
}

// LocalClassifyClassification holds classification tuning settings.
type LocalClassifyClassification struct {
	ConfidenceThreshold float64 `json:"confidence_threshold,omitempty"`
	DefaultLabel        string  `json:"default_label,omitempty"`
}

type localClassifyGuardrail struct {
	config LocalClassifyConfig
}

// NewLocalClassifyGuardrail creates a guardrail that uses the classifier sidecar
// to pre-screen requests by label. Requests matching block labels above the
// threshold are rejected. Requests matching safe labels above the safe threshold
// pass and may skip downstream guardrails.
func NewLocalClassifyGuardrail(config json.RawMessage) (Guardrail, error) {
	cfg := LocalClassifyConfig{
		BlockThreshold: 0.7,
		SafeThreshold:  0.85,
	}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, fmt.Errorf("local_classify config: %w", err)
		}
	}
	return &localClassifyGuardrail{config: cfg}, nil
}

// Name returns the guardrail identifier.
func (g *localClassifyGuardrail) Name() string { return "local_classify" }

// Phase returns the phase at which this guardrail runs (input).
func (g *localClassifyGuardrail) Phase() Phase { return PhaseInput }

// Check evaluates content against the classifier sidecar and returns a result.
// Block labels above the block threshold cause the request to be rejected.
// Safe labels above the safe threshold allow the request and may skip downstream guardrails.
// When the sidecar is unavailable, the guardrail fails open.
func (g *localClassifyGuardrail) Check(_ context.Context, content *Content) (*Result, error) {
	mc := classifier.Global()
	if mc == nil || !mc.IsAvailable() {
		// Fail open when sidecar is unavailable
		return &Result{Pass: true, Reason: "classifier sidecar unavailable"}, nil
	}

	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true}, nil
	}

	// Request enough labels to cover both block and safe lists
	topK := len(g.config.BlockLabels) + len(g.config.SafeLabels)
	if topK < 3 {
		topK = 3
	}

	result, err := mc.ClassifyForTenant(text, topK, "")
	if err != nil {
		slog.Debug("local_classify: classification error, passing", "error", err)
		return &Result{Pass: true, Reason: "classification error, fail open"}, nil
	}

	if len(result.Labels) == 0 {
		return &Result{Pass: true}, nil
	}

	// Check block labels
	for _, label := range result.Labels {
		if containsString(g.config.BlockLabels, label.Label) && label.Score >= g.config.BlockThreshold {
			return &Result{
				Pass:   false,
				Reason: fmt.Sprintf("blocked by local classification: %s (score: %.2f)", label.Label, label.Score),
				Score:  label.Score,
				Details: map[string]any{
					"label":     label.Label,
					"threshold": g.config.BlockThreshold,
				},
			}, nil
		}
	}

	// Check safe labels (for skip logic)
	for _, label := range result.Labels {
		if containsString(g.config.SafeLabels, label.Label) && label.Score >= g.config.SafeThreshold {
			return &Result{
				Pass:   true,
				Reason: fmt.Sprintf("safe classification: %s (score: %.2f)", label.Label, label.Score),
				Score:  label.Score,
				Details: map[string]any{
					"label":           label.Label,
					"skip_guardrails": g.config.SafeSkipGuardrails,
				},
			}, nil
		}
	}

	return &Result{Pass: true}, nil
}

// Transform is a no-op for the local classify guardrail.
func (g *localClassifyGuardrail) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
