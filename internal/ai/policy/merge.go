package policy

import (
	"sort"
)

// MergePolicies combines multiple policies (from a user's groups) into an effective policy.
// Rules:
//   - Numeric limits: take the MAXIMUM (most permissive) across groups
//   - Model/provider lists: UNION of allowed, INTERSECTION of blocked
//   - Booleans: OR (if any policy allows, it is allowed)
//   - Priority: lowest priority number wins for conflicts
func MergePolicies(policies []*Policy) *Policy {
	if len(policies) == 0 {
		return &Policy{}
	}
	if len(policies) == 1 {
		cp := *policies[0]
		return &cp
	}

	// Sort by priority (lowest first) so the highest priority policy is base.
	sorted := make([]*Policy, len(policies))
	copy(sorted, policies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	// Start with the highest priority policy as the base.
	base := sorted[0]
	merged := &Policy{
		ID:               base.ID,
		Name:             base.Name,
		Priority:         base.Priority,
		MaxInputTokens:   base.MaxInputTokens,
		MaxOutputTokens:  base.MaxOutputTokens,
		MaxTotalTokens:   base.MaxTotalTokens,
		RPM:              base.RPM,
		TPM:              base.TPM,
		RPD:              base.RPD,
		AllowStreaming:    copyBoolPtr(base.AllowStreaming),
		AllowTools:       copyBoolPtr(base.AllowTools),
		AllowImages:      copyBoolPtr(base.AllowImages),
		RequireGuardrails: base.RequireGuardrails,
	}

	// Collect allowed and blocked lists.
	allowedModelsSet := make(map[string]struct{})
	blockedModelsSet := make(map[string]struct{})
	allowedProvidersSet := make(map[string]struct{})
	blockedProvidersSet := make(map[string]struct{})

	// Seed blocked sets from first policy (for intersection).
	blockedModelsInit := false
	blockedProvidersInit := false

	for _, p := range sorted {
		// UNION of allowed reqctx.
		for _, m := range p.AllowedModels {
			allowedModelsSet[m] = struct{}{}
		}

		// INTERSECTION of blocked reqctx.
		if len(p.BlockedModels) > 0 {
			if !blockedModelsInit {
				for _, m := range p.BlockedModels {
					blockedModelsSet[m] = struct{}{}
				}
				blockedModelsInit = true
			} else {
				current := make(map[string]struct{})
				for _, m := range p.BlockedModels {
					current[m] = struct{}{}
				}
				for m := range blockedModelsSet {
					if _, ok := current[m]; !ok {
						delete(blockedModelsSet, m)
					}
				}
			}
		} else if blockedModelsInit {
			// If a policy has no blocked models, the intersection is empty.
			blockedModelsSet = make(map[string]struct{})
		}

		// UNION of allowed providers.
		for _, pr := range p.AllowedProviders {
			allowedProvidersSet[pr] = struct{}{}
		}

		// INTERSECTION of blocked providers.
		if len(p.BlockedProviders) > 0 {
			if !blockedProvidersInit {
				for _, pr := range p.BlockedProviders {
					blockedProvidersSet[pr] = struct{}{}
				}
				blockedProvidersInit = true
			} else {
				current := make(map[string]struct{})
				for _, pr := range p.BlockedProviders {
					current[pr] = struct{}{}
				}
				for pr := range blockedProvidersSet {
					if _, ok := current[pr]; !ok {
						delete(blockedProvidersSet, pr)
					}
				}
			}
		} else if blockedProvidersInit {
			blockedProvidersSet = make(map[string]struct{})
		}

		// Numeric limits: take MAXIMUM (most permissive).
		if p.MaxInputTokens > merged.MaxInputTokens {
			merged.MaxInputTokens = p.MaxInputTokens
		}
		if p.MaxOutputTokens > merged.MaxOutputTokens {
			merged.MaxOutputTokens = p.MaxOutputTokens
		}
		if p.MaxTotalTokens > merged.MaxTotalTokens {
			merged.MaxTotalTokens = p.MaxTotalTokens
		}
		if p.RPM > merged.RPM {
			merged.RPM = p.RPM
		}
		if p.TPM > merged.TPM {
			merged.TPM = p.TPM
		}
		if p.RPD > merged.RPD {
			merged.RPD = p.RPD
		}

		// Booleans: OR (if any allows, it is allowed).
		merged.AllowStreaming = mergeBoolOR(merged.AllowStreaming, p.AllowStreaming)
		merged.AllowTools = mergeBoolOR(merged.AllowTools, p.AllowTools)
		merged.AllowImages = mergeBoolOR(merged.AllowImages, p.AllowImages)

		// Guardrails: require only if ALL policies require it (AND logic for requirements).
		// Actually, the spec says OR for booleans. RequireGuardrails is a requirement, not a permission,
		// so if ANY policy requires guardrails, they are required.
		if p.RequireGuardrails {
			merged.RequireGuardrails = true
		}
	}

	// Convert sets to slices.
	merged.AllowedModels = setToSortedSlice(allowedModelsSet)
	merged.BlockedModels = setToSortedSlice(blockedModelsSet)
	merged.AllowedProviders = setToSortedSlice(allowedProvidersSet)
	merged.BlockedProviders = setToSortedSlice(blockedProvidersSet)

	// Merge tags.
	tagMap := make(map[string]string)
	for i := len(sorted) - 1; i >= 0; i-- {
		for k, v := range sorted[i].Tags {
			tagMap[k] = v
		}
	}
	if len(tagMap) > 0 {
		merged.Tags = tagMap
	}

	return merged
}

// mergeBoolOR merges two optional booleans with OR logic.
// If either is true, the result is true.
func mergeBoolOR(a, b *bool) *bool {
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		cp := *b
		return &cp
	}
	if b == nil {
		cp := *a
		return &cp
	}
	result := *a || *b
	return &result
}

// copyBoolPtr returns a copy of a bool pointer.
func copyBoolPtr(b *bool) *bool {
	if b == nil {
		return nil
	}
	cp := *b
	return &cp
}

// setToSortedSlice converts a set to a sorted slice.
func setToSortedSlice(s map[string]struct{}) []string {
	if len(s) == 0 {
		return nil
	}
	result := make([]string, 0, len(s))
	for k := range s {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}
