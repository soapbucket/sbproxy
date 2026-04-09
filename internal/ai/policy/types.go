// Package policy implements a 9-stage policy evaluation pipeline for the AI gateway.
// Policies define what principals can do: model access, token limits, rate limits,
// guardrail requirements, and feature gating.
package policy

// Principal is the interface for authenticated identities used in policy evaluation.
// This avoids a direct dependency on the identity package (which transitively depends
// on the ai package). The identity.Principal struct satisfies this interface.
type Principal interface {
	// GetID returns the principal's unique identifier.
	GetID() string
	// IsExpired returns true if the principal's credentials have expired.
	IsExpired() bool
}

// Policy defines access controls and limits for AI gateway usage.
type Policy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Priority int    `json:"priority"` // Lower = higher priority

	// Model access
	AllowedModels []string `json:"allowed_models,omitempty"`
	BlockedModels []string `json:"blocked_models,omitempty"`

	// Provider access
	AllowedProviders []string `json:"allowed_providers,omitempty"`
	BlockedProviders []string `json:"blocked_providers,omitempty"`

	// Token limits (per request)
	MaxInputTokens  int64 `json:"max_input_tokens,omitempty"`
	MaxOutputTokens int64 `json:"max_output_tokens,omitempty"`
	MaxTotalTokens  int64 `json:"max_total_tokens,omitempty"`

	// Rate limits
	RPM int   `json:"rpm,omitempty"` // Requests per minute
	TPM int64 `json:"tpm,omitempty"` // Tokens per minute
	RPD int   `json:"rpd,omitempty"` // Requests per day

	// Feature flags
	AllowStreaming    *bool `json:"allow_streaming,omitempty"`
	AllowTools        *bool `json:"allow_tools,omitempty"`
	AllowImages       *bool `json:"allow_images,omitempty"`
	RequireGuardrails bool  `json:"require_guardrails,omitempty"`

	// Required tags that must be present on the request
	RequiredTags map[string]string `json:"required_tags,omitempty"`

	// Metadata
	Tags map[string]string `json:"tags,omitempty"`
}

// EvaluationContext holds request data for policy evaluation.
type EvaluationContext struct {
	Principal    Principal
	Model        string
	Provider     string
	InputTokens  int64
	OutputTokens int64
	IsStreaming   bool
	HasTools     bool
	HasImages    bool
	// GuardrailsConfigured indicates whether guardrails are set up for this request.
	GuardrailsConfigured bool
	Tags                 map[string]string
}

// EvaluationResult is the outcome of a policy evaluation.
type EvaluationResult struct {
	Allowed         bool     `json:"allowed"`
	DeniedBy        string   `json:"denied_by,omitempty"`   // Stage name that denied
	Reason          string   `json:"reason,omitempty"`      // Human-readable reason
	Warnings        []string `json:"warnings,omitempty"`    // Non-blocking warnings
	AppliedPolicies []string `json:"applied_policies,omitempty"`
}

// StageResult is the outcome of a single pipeline stage.
type StageResult struct {
	Allowed  bool
	Reason   string
	Warnings []string
}

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool {
	return &b
}
