// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

// ComplexityRoutingConfig maps complexity levels to model names.
type ComplexityRoutingConfig struct {
	Low    string `json:"low,omitempty"`
	Medium string `json:"medium,omitempty"`
	High   string `json:"high,omitempty"`
	Code   string `json:"code,omitempty"`
}

// MirrorConfig configures traffic mirroring for AI requests.
type MirrorConfig struct {
	Enabled     bool    `json:"enabled"`
	TargetModel string  `json:"target_model,omitempty"`
	SampleRate  float64 `json:"sample_rate,omitempty"`
}
