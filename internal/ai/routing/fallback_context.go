package routing

import (
	"log/slog"
	"sort"

	"github.com/soapbucket/sbproxy/internal/ai"
)

// ContextFallbackMap finds models with larger context windows when a request
// exceeds the current model's limits. It supports both explicit user-configured
// fallbacks and auto-generated fallbacks derived from the provider registry.
type ContextFallbackMap struct {
	configured map[string]string  // Explicit overrides, e.g. "gpt-4" -> "gpt-4-turbo-128k"
	registry   *ai.ProviderRegistry // Used to auto-generate fallbacks within the same provider
}

// NewContextFallbackMap creates a fallback map. configured may be nil.
func NewContextFallbackMap(configured map[string]string, registry *ai.ProviderRegistry) *ContextFallbackMap {
	if configured == nil {
		configured = make(map[string]string)
	}
	return &ContextFallbackMap{
		configured: configured,
		registry:   registry,
	}
}

// FindLarger returns a model with a context window large enough to fit
// requiredTokens. It checks explicit configured fallbacks first, then
// auto-generates candidates from the same provider in the registry.
// Returns the model name and true if found, or ("", false) if no suitable
// fallback exists.
func (m *ContextFallbackMap) FindLarger(model string, requiredTokens int) (string, bool) {
	// 1. Check explicit configured fallback.
	if target, ok := m.configured[model]; ok {
		if m.registry != nil {
			targetDef, _, found := m.registry.GetModel(target)
			if found && targetDef.ContextWindow >= requiredTokens {
				slog.Debug("context fallback: using configured fallback",
					"from", model, "to", target, "required", requiredTokens,
					"target_window", targetDef.ContextWindow)
				return target, true
			}
		} else {
			// No registry to verify - trust the configured mapping.
			return target, true
		}
	}

	// 2. Auto-generate: find a model from the same provider with a larger window.
	if m.registry == nil {
		return "", false
	}

	sourceDef, sourceProvider, ok := m.registry.GetModel(model)
	if !ok {
		return "", false
	}

	providerDef, providerOK := m.registry.GetProvider(sourceProvider)
	if !providerOK {
		return "", false
	}

	// Collect candidates with a larger context window that fits the requirement.
	type candidate struct {
		name   string
		window int
	}
	var candidates []candidate

	for modelName, modelDef := range providerDef.Models {
		if modelName == model {
			continue
		}
		if modelDef.ContextWindow <= sourceDef.ContextWindow {
			continue
		}
		if modelDef.ContextWindow < requiredTokens {
			continue
		}
		candidates = append(candidates, candidate{name: modelName, window: modelDef.ContextWindow})
	}

	if len(candidates) == 0 {
		return "", false
	}

	// Pick the smallest sufficient window to avoid unnecessary cost escalation.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].window < candidates[j].window
	})

	best := candidates[0]
	slog.Debug("context fallback: auto-generated fallback",
		"from", model, "to", best.name, "required", requiredTokens,
		"source_window", sourceDef.ContextWindow, "target_window", best.window)
	return best.name, true
}
