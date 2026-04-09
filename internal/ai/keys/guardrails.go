package keys

// CELGuardrailConfig is the configuration for a single CEL guardrail expression.
// This mirrors the ai.CELGuardrailConfig struct to avoid circular imports between
// the keys and ai packages.
type CELGuardrailConfig struct {
	Name      string `json:"name" yaml:"name"`
	Phase     string `json:"phase" yaml:"phase"`         // "input" or "output"
	Condition string `json:"condition" yaml:"condition"` // CEL expression returning bool
	Action    string `json:"action" yaml:"action"`       // "block" or "flag"
	Message   string `json:"message,omitempty" yaml:"message,omitempty"`
}

// ResolveGuardrails returns the effective guardrail expressions for a key.
// If the key has its own guardrail expressions, those are used. Otherwise,
// the origin-level defaults are returned.
func ResolveGuardrails(key *VirtualKey, originGuardrails []CELGuardrailConfig) []CELGuardrailConfig {
	if key != nil && len(key.GuardrailExpressions) > 0 {
		return key.GuardrailExpressions
	}
	return originGuardrails
}
