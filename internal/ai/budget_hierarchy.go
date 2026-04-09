// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"sort"
	"sync"
)

// BudgetScope represents a level in the budget hierarchy.
type BudgetScope struct {
	Type  string `json:"type"`  // "workspace", "user", "group", "model", "provider", "api_key", "tag"
	Value string `json:"value"` // The specific ID/name
}

// BudgetHierarchy resolves the applicable budget limit by walking from most-specific to least-specific.
type BudgetHierarchy struct {
	limits []HierarchicalLimit
	mu     sync.RWMutex
}

// HierarchicalLimit defines a token budget limit at a specific scope level.
type HierarchicalLimit struct {
	Scopes           []BudgetScope `json:"scopes"`             // compound scope (e.g., user+model)
	Period           string        `json:"period"`             // "minute", "hour", "day", "month"
	InputTokenLimit  int64         `json:"input_token_limit"`  // 0 = unlimited
	OutputTokenLimit int64         `json:"output_token_limit"` // 0 = unlimited
	TotalTokenLimit  int64         `json:"total_token_limit"`  // 0 = unlimited
	Action           string        `json:"action"`             // "block", "log", "downgrade"
	Priority         int           `json:"priority"`           // lower = more specific = checked first
}

// NewBudgetHierarchy creates a new budget hierarchy from a set of limits.
// Limits are sorted by priority (lowest first, most specific).
func NewBudgetHierarchy(limits []HierarchicalLimit) *BudgetHierarchy {
	sorted := make([]HierarchicalLimit, len(limits))
	copy(sorted, limits)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	return &BudgetHierarchy{
		limits: sorted,
	}
}

// Resolve finds the most specific applicable limit for the given scope values.
// It walks from most-specific (lowest priority number) to least-specific,
// returning the first limit whose scopes all match provided values.
func (h *BudgetHierarchy) Resolve(scopes map[string]string) *HierarchicalLimit {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for i := range h.limits {
		if h.limitMatchesScopes(&h.limits[i], scopes) {
			result := h.limits[i]
			return &result
		}
	}
	return nil
}

// ResolveAll returns all applicable limits for the given scope values,
// ordered from most specific to least specific.
func (h *BudgetHierarchy) ResolveAll(scopes map[string]string) []HierarchicalLimit {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var result []HierarchicalLimit
	for i := range h.limits {
		if h.limitMatchesScopes(&h.limits[i], scopes) {
			result = append(result, h.limits[i])
		}
	}
	return result
}

// UpdateLimits replaces the hierarchy limits with a new set.
func (h *BudgetHierarchy) UpdateLimits(limits []HierarchicalLimit) {
	sorted := make([]HierarchicalLimit, len(limits))
	copy(sorted, limits)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	h.mu.Lock()
	h.limits = sorted
	h.mu.Unlock()
}

// limitMatchesScopes returns true if every scope in the limit has a matching value
// in the provided scope map.
func (h *BudgetHierarchy) limitMatchesScopes(limit *HierarchicalLimit, scopes map[string]string) bool {
	if len(limit.Scopes) == 0 {
		return false
	}
	for _, s := range limit.Scopes {
		val, ok := scopes[s.Type]
		if !ok || val == "" {
			return false
		}
		// If the limit scope has a specific value, it must match exactly.
		// If the scope value is "*", it matches any non-empty value.
		if s.Value != "*" && s.Value != "" && s.Value != val {
			return false
		}
	}
	return true
}
