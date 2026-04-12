// Package keys provides AI virtual key management for multi-tenant access control.
package keys

import (
	"strings"
	"time"
)

// VirtualKey represents an AI virtual key for multi-tenant access control.
type VirtualKey struct {
	ID                string            `json:"id"`                              // "sk-sb-..." prefix
	Name              string            `json:"name"`
	HashedKey         string            `json:"hashed_key"`                      // SHA256 of raw key
	WorkspaceID       string            `json:"workspace_id"`
	TeamID            string            `json:"team_id,omitempty"`
	CreatedBy         string            `json:"created_by,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
	Status            string            `json:"status"`                          // "active", "revoked", "expired"
	AllowedModels     []string          `json:"allowed_models,omitempty"`
	BlockedModels     []string          `json:"blocked_models,omitempty"`
	AllowedProviders  []string          `json:"allowed_providers,omitempty"`
	MaxTokensPerMin   int               `json:"max_tokens_per_min,omitempty"`
	MaxRequestsPerMin int               `json:"max_requests_per_min,omitempty"`
	MaxBudgetUSD      float64           `json:"max_budget_usd,omitempty"`
	BudgetPeriod      string            `json:"budget_period,omitempty"`         // "daily", "monthly", "total"
	MaxTokens         int64             `json:"max_tokens,omitempty"`            // Token-based budget limit
	TokenBudgetAction string            `json:"token_budget_action,omitempty"`   // "block" (default) or "downgrade"
	DowngradeMap      map[string]string `json:"downgrade_map,omitempty"`         // model -> cheaper model (when action="downgrade")
	ProviderKeys      map[string]string `json:"provider_keys,omitempty"`         // provider_name -> API key
	ModelAliases      map[string]string `json:"model_aliases,omitempty"`         // alias -> actual model (e.g., "fast" -> "gpt-4o-mini")
	Metadata          map[string]string `json:"metadata,omitempty"`

	// Role controls access level: "admin" (all models, no limits), "user" (enforced), "readonly" (403).
	// Defaults to "user" if empty.
	Role string `json:"role,omitempty"`

	// GuardrailExpressions overrides origin-level CEL guardrails when set.
	GuardrailExpressions []CELGuardrailConfig `json:"guardrail_expressions,omitempty"`

	// ToolFilter restricts which MCP tools this key can access.
	ToolFilter *ToolFilter `json:"tool_filter,omitempty"`

	// ProjectID links this key to a project for hierarchical budget enforcement.
	ProjectID string `json:"project_id,omitempty"`
}

// IsActive returns true if the key is active and not expired.
func (vk *VirtualKey) IsActive() bool {
	if vk.Status != "active" {
		return false
	}
	if vk.ExpiresAt != nil && time.Now().After(*vk.ExpiresAt) {
		return false
	}
	return true
}

// IsModelAllowed returns true if the given model is allowed by this key.
func (vk *VirtualKey) IsModelAllowed(model string) bool {
	// Check blocked models first
	for _, blocked := range vk.BlockedModels {
		if strings.EqualFold(blocked, model) {
			return false
		}
	}
	// If no allowed models specified, all non-blocked models are allowed
	if len(vk.AllowedModels) == 0 {
		return true
	}
	for _, allowed := range vk.AllowedModels {
		if strings.EqualFold(allowed, model) {
			return true
		}
	}
	return false
}

// IsProviderAllowed returns true if the given provider is allowed by this key.
func (vk *VirtualKey) IsProviderAllowed(provider string) bool {
	if len(vk.AllowedProviders) == 0 {
		return true
	}
	for _, allowed := range vk.AllowedProviders {
		if strings.EqualFold(allowed, provider) {
			return true
		}
	}
	return false
}

// UsageStore defines the interface for virtual key usage tracking.
// Both in-memory (UsageTracker) and Redis-backed (RedisUsageTracker) implement this.
type UsageStore interface {
	Record(keyID string, inputTokens, outputTokens int, costUSD float64, isError bool)
	GetUsage(keyID string) *KeyUsage
	CheckBudget(keyID string, maxBudgetUSD float64, budgetPeriod string) bool
	CheckTokenBudget(keyID string, maxTokens int64) bool
	CheckTokenRate(keyID string, maxTokensPerMin int) bool
	TokenUtilization(keyID string, maxTokens int64) float64
	Reset(keyID string)
}

// KeyUsage tracks per-key resource consumption.
type KeyUsage struct {
	KeyID       string    `json:"key_id"`
	Requests    int64     `json:"requests"`
	InputTokens int64    `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalTokens int64    `json:"total_tokens"`
	CostUSD     float64  `json:"cost_usd"`
	Errors      int64    `json:"errors"`
	Period      string   `json:"period"`       // "daily", "monthly", "total"
	PeriodStart time.Time `json:"period_start"`
}

// ListOpts configures listing virtual keys.
type ListOpts struct {
	Status string
	Limit  int
	Offset int
}

// ToolFilter restricts which MCP tools a virtual key can access.
type ToolFilter struct {
	// Include patterns - only tools matching at least one pattern pass. Empty = include all.
	Include []string `json:"include,omitempty"`
	// Exclude patterns - tools matching any pattern are removed. Applied after include.
	Exclude []string `json:"exclude,omitempty"`
	// IncludeTags - only tools with at least one matching tag pass. Empty = no tag filter.
	IncludeTags []string `json:"include_tags,omitempty"`
	// ExcludeTags - tools with any matching tag are removed.
	ExcludeTags []string `json:"exclude_tags,omitempty"`
}

// CELGuardrailConfig is the configuration for a single CEL guardrail expression.
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
