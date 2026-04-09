// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"net/http"
	"sort"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// modelsCreatedEpoch is a fixed timestamp used for models that have no creation date.
// Set to 2024-01-01T00:00:00Z for consistency.
var modelsCreatedEpoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

// handleListModels responds to GET /v1/models with an OpenAI-compatible model list.
// It aggregates models from all configured providers, the gateway model registry,
// deduplicates by model ID (first provider wins), filters by feature flags, and
// returns the list sorted alphabetically by ID.
func (h *Handler) handleListModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	seen := make(map[string]bool)
	var allModels []ModelInfo

	// Step 1: Aggregate models from all configured providers.
	// Models returned by the provider's ListModels call take priority, followed
	// by models declared in the provider config's Models field.
	for _, entry := range h.providers {
		// Try the provider's live model listing first.
		providerModels, err := entry.provider.ListModels(r.Context(), entry.config)
		if err == nil {
			for _, m := range providerModels {
				if seen[m.ID] {
					continue
				}
				seen[m.ID] = true
				if m.Object == "" {
					m.Object = "model"
				}
				if m.OwnedBy == "" {
					m.OwnedBy = entry.config.Name
				}
				if m.Created == 0 {
					m.Created = modelsCreatedEpoch
				}
				allModels = append(allModels, m)
			}
		}

		// Add models declared in the provider config that were not already seen.
		for _, model := range entry.config.Models {
			if seen[model] {
				continue
			}
			seen[model] = true
			allModels = append(allModels, ModelInfo{
				ID:      model,
				Object:  "model",
				Created: modelsCreatedEpoch,
				OwnedBy: entry.config.Name,
			})
		}
	}

	// Step 2: Add models from the gateway model registry if configured.
	if h.config.Gateway && h.config.ModelRegistry != nil {
		for _, pattern := range h.config.ModelRegistry.Models() {
			// Skip glob patterns - they are not concrete model IDs.
			if strings.ContainsAny(pattern, "*?[") {
				continue
			}
			if seen[pattern] {
				continue
			}
			seen[pattern] = true
			ownedBy := "gateway"
			if provider, _, found := h.config.ModelRegistry.Lookup(pattern); found {
				ownedBy = provider
			}
			allModels = append(allModels, ModelInfo{
				ID:      pattern,
				Object:  "model",
				Created: modelsCreatedEpoch,
				OwnedBy: ownedBy,
			})
		}
	}

	// Step 3: Filter out models disabled by feature flags.
	// A model is excluded when the flag "ai.models.<id>.enabled" is explicitly false.
	allModels = h.filterModelsByFeatureFlags(r, allModels)

	// Step 4: Sort alphabetically by model ID.
	sort.Slice(allModels, func(i, j int) bool {
		return allModels[i].ID < allModels[j].ID
	})

	// Ensure Data is never null in JSON output.
	if allModels == nil {
		allModels = []ModelInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ModelListResponse{
		Object: "list",
		Data:   allModels,
	})
}

// filterModelsByFeatureFlags removes models whose feature flag
// "ai.models.<id>.enabled" is explicitly set to false.
func (h *Handler) filterModelsByFeatureFlags(r *http.Request, models []ModelInfo) []ModelInfo {
	rd := reqctx.GetRequestData(r.Context())
	if rd == nil || len(rd.FeatureFlags) == 0 {
		return models
	}

	filtered := make([]ModelInfo, 0, len(models))
	for _, m := range models {
		flagKey := "ai.models." + m.ID + ".enabled"
		if val, ok := rd.FeatureFlags[flagKey]; ok {
			if enabled, isBool := val.(bool); isBool && !enabled {
				continue
			}
		}
		filtered = append(filtered, m)
	}
	return filtered
}
