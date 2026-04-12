// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"log/slog"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// effectiveBudget returns the base budget amount adjusted by any feature flag
// override for the given scope. The override key follows the pattern
// "ai.budget.override_<scope>" (e.g., "ai.budget.override_workspace").
// When a matching flag exists and its value is a positive number, it is added
// to the base budget. When no override is found, baseBudget is returned unchanged.
func effectiveBudget(flags map[string]any, scope string, baseBudget float64) float64 {
	if len(flags) == 0 {
		return baseBudget
	}
	overrideKey := fmt.Sprintf("ai.budget.override_%s", scope)
	val, exists := flags[overrideKey]
	if !exists {
		return baseBudget
	}
	additional, ok := val.(float64)
	if !ok || additional <= 0 {
		return baseBudget
	}
	slog.Debug("budget override applied",
		"scope", scope,
		"base", baseBudget,
		"additional", additional,
		"effective", baseBudget+additional,
	)
	return baseBudget + additional
}

// applyBudgetFlagOverrides returns a copy of the budget config with limits
// adjusted by feature flag overrides. The original config is not modified.
// If flags is nil or no overrides match, the original config is returned as-is.
func applyBudgetFlagOverrides(cfg *BudgetConfig, flags map[string]any) *BudgetConfig {
	if cfg == nil || len(flags) == 0 {
		return cfg
	}

	// Check if any overrides exist before copying.
	hasOverride := false
	for _, limit := range cfg.Limits {
		overrideKey := fmt.Sprintf("ai.budget.override_%s", limit.Scope)
		if _, exists := flags[overrideKey]; exists {
			hasOverride = true
			break
		}
	}
	if !hasOverride {
		return cfg
	}

	// Build a new config with adjusted limits.
	adjusted := *cfg
	adjusted.Limits = make([]BudgetLimit, len(cfg.Limits))
	copy(adjusted.Limits, cfg.Limits)

	for i, limit := range adjusted.Limits {
		if limit.MaxCostUSD > 0 {
			adjusted.Limits[i].MaxCostUSD = effectiveBudget(flags, limit.Scope, limit.MaxCostUSD)
		}
		if limit.MaxTokens > 0 {
			overrideKey := fmt.Sprintf("ai.budget.override_%s", limit.Scope)
			if val, exists := flags[overrideKey]; exists {
				if additional, ok := val.(float64); ok && additional > 0 {
					// For token limits, treat the override as a multiplier fraction of original.
					// e.g., override=0.5 on a 1000-token limit yields 1500 tokens.
					adjusted.Limits[i].MaxTokens += int64(additional * float64(limit.MaxTokens))
				}
			}
		}
	}

	return &adjusted
}

// getWorkspaceFlags extracts feature flags from the request data.
// Returns nil if no flags are available.
func getWorkspaceFlags(rd *reqctx.RequestData) map[string]any {
	if rd == nil {
		return nil
	}
	return rd.FeatureFlags
}
