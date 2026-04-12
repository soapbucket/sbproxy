// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	json "github.com/goccy/go-json"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai"
)

// Phase indicates when a guardrail runs.
type Phase string

const (
	// PhaseInput is a constant for phase input.
	PhaseInput  Phase = "input"
	// PhaseOutput is a constant for phase output.
	PhaseOutput Phase = "output"
)

// Action determines what happens when a guardrail triggers.
type Action string

const (
	// ActionAllow is a constant for action allow.
	ActionAllow     Action = "allow"
	// ActionBlock is a constant for action block.
	ActionBlock     Action = "block"
	// ActionTransform is a constant for action transform.
	ActionTransform Action = "transform"
	// ActionFlag is a constant for action flag.
	ActionFlag      Action = "flag"
)

// Guardrail processes content for safety, compliance, or quality.
type Guardrail interface {
	// Name returns the guardrail identifier.
	Name() string

	// Phase returns when this guardrail runs (input, output).
	Phase() Phase

	// Check evaluates content and returns a result.
	Check(ctx context.Context, content *Content) (*Result, error)

	// Transform modifies content (e.g., PII redaction).
	// Only called if the guardrail's action is "transform".
	Transform(ctx context.Context, content *Content) (*Content, error)
}

// Content holds the messages being evaluated.
type Content struct {
	Messages []ai.Message `json:"messages"`
	Text     string       `json:"text,omitempty"`
	Model    string       `json:"model,omitempty"`
}

// ExtractText concatenates all message text content.
func (c *Content) ExtractText() string {
	if c.Text != "" {
		return c.Text
	}
	var text string
	for i := range c.Messages {
		s := c.Messages[i].ContentString()
		if s != "" {
			if text != "" {
				text += "\n"
			}
			text += s
		}
	}
	return text
}

// Result holds the outcome of a guardrail check.
type Result struct {
	Guardrail string         `json:"guardrail"`
	Pass      bool           `json:"pass"`
	Action    Action         `json:"action"`
	Reason    string         `json:"reason,omitempty"`
	Score     float64        `json:"score,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	Latency   time.Duration  `json:"-"`
}

// MarshalJSON implements custom JSON marshaling for Result,
// converting Latency from time.Duration (nanoseconds) to milliseconds
// so the JSON field "latency_ms" contains a human-friendly value.
func (r Result) MarshalJSON() ([]byte, error) {
	type Alias Result
	return json.Marshal(&struct {
		Alias
		LatencyMs float64 `json:"latency_ms,omitempty"`
	}{
		Alias:     Alias(r),
		LatencyMs: float64(r.Latency) / float64(time.Millisecond),
	})
}

// GuardrailsConfig configures the guardrail pipeline.
type GuardrailsConfig struct {
	Input    []GuardrailEntry `json:"input,omitempty"`
	Output   []GuardrailEntry `json:"output,omitempty"`
	Parallel bool             `json:"parallel,omitempty"`
}

// GuardrailEntry defines a single guardrail in the pipeline.
type GuardrailEntry struct {
	Type   string          `json:"type"`
	Action Action          `json:"action,omitempty"`
	Config json.RawMessage `json:"config,omitempty"`
}
