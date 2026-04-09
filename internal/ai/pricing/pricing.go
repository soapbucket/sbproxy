// Package pricing calculates token-based costs for AI model usage across providers.
package pricing

import (
	json "github.com/goccy/go-json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// commonProviderPrefixes lists provider prefixes used for flexible model lookup.
var commonProviderPrefixes = []string{
	"openai/",
	"anthropic/",
	"google/",
	"bedrock/",
	"azure/",
	"vertex_ai/",
	"cohere/",
	"mistral/",
	"groq/",
	"together_ai/",
}

// ModelPricing holds per-model pricing data.
type ModelPricing struct {
	InputPerMToken        float64 `json:"input_per_m_token"`
	OutputPerMToken       float64 `json:"output_per_m_token"`
	CachedInputPerMToken  float64 `json:"cached_input_per_m_token,omitempty"`
	EmbeddingPerMToken    float64 `json:"embedding_per_m_token,omitempty"`
	CacheWritePerMToken   float64 `json:"cache_write_per_m_token,omitempty"`
	ReasoningPerMToken    float64 `json:"reasoning_per_m_token,omitempty"`
}

// Source provides model pricing data.
type Source struct {
	pricing   map[string]*ModelPricing
	overrides map[string]*ModelPricing
	mu        sync.RWMutex
}

// global holds a shared pricing source initialized at startup.
var global atomic.Pointer[Source]

// SetGlobal sets the global pricing source for use by all AI proxy actions.
func SetGlobal(s *Source) { global.Store(s) }

// Global returns the global pricing source. Returns nil if not initialized.
func Global() *Source { return global.Load() }

// SourceConfig configures the pricing source.
type SourceConfig struct {
	Overrides map[string]*ModelPricing `json:"overrides,omitempty"`
}

// NewSource creates a new pricing source with an empty pricing map and optional overrides.
// Use LoadFile to populate pricing data from a LiteLLM-format JSON file.
func NewSource(cfg *SourceConfig) *Source {
	s := &Source{
		pricing: make(map[string]*ModelPricing),
	}
	if cfg != nil {
		s.overrides = cfg.Overrides
	}
	return s
}

// GetPricing returns pricing for a model using flexible lookup. Returns nil if not found.
// Lookup order: exact match, stripped provider prefix, common provider prefixes.
func (s *Source) GetPricing(model string) *ModelPricing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getPricingLocked(model)
}

// GetPricingWithProvider returns pricing for a model, preferring a provider-qualified key.
// Lookup order: exact match, provider/model, model without prefix, common prefixes, nil.
func (s *Source) GetPricingWithProvider(model, provider string) *ModelPricing {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. Exact match (includes overrides)
	if p := s.lookupExact(model); p != nil {
		return p
	}

	// 2. Try provider/model if provider is given
	if provider != "" {
		qualified := provider + "/" + model
		if p := s.lookupExact(qualified); p != nil {
			return p
		}
	}

	// 3. Strip any existing prefix and try the base name
	if idx := strings.Index(model, "/"); idx >= 0 {
		base := model[idx+1:]
		if p := s.lookupExact(base); p != nil {
			return p
		}
	}

	// 4. Try common provider prefixes
	return s.tryProviderPrefixes(model)
}

// lookupExact checks overrides then pricing map for an exact key. Must hold mu.RLock.
func (s *Source) lookupExact(model string) *ModelPricing {
	if s.overrides != nil {
		if p, ok := s.overrides[model]; ok {
			return p
		}
	}
	if p, ok := s.pricing[model]; ok {
		return p
	}
	return nil
}

// getPricingLocked performs flexible lookup. Must hold mu.RLock.
func (s *Source) getPricingLocked(model string) *ModelPricing {
	// 1. Exact match
	if p := s.lookupExact(model); p != nil {
		return p
	}

	// 2. If model has a provider prefix (e.g. "openai/gpt-4o"), try the base name
	if idx := strings.Index(model, "/"); idx >= 0 {
		base := model[idx+1:]
		if p := s.lookupExact(base); p != nil {
			return p
		}
	}

	// 3. Try common provider prefixes (e.g. "gpt-4o" -> "openai/gpt-4o")
	return s.tryProviderPrefixes(model)
}

// tryProviderPrefixes tries common provider-prefixed keys. Must hold mu.RLock.
func (s *Source) tryProviderPrefixes(model string) *ModelPricing {
	// Don't try prefixes if the model already has one
	if strings.Contains(model, "/") {
		return nil
	}
	for _, prefix := range commonProviderPrefixes {
		if p, ok := s.pricing[prefix+model]; ok {
			return p
		}
	}
	return nil
}

// CalculateCost returns the cost in USD for the given token counts.
func (s *Source) CalculateCost(model string, inputTokens, outputTokens, cachedTokens int) float64 {
	p := s.GetPricing(model)
	if p == nil {
		return 0
	}

	cost := float64(inputTokens) * p.InputPerMToken / 1_000_000
	cost += float64(outputTokens) * p.OutputPerMToken / 1_000_000
	if cachedTokens > 0 && p.CachedInputPerMToken > 0 {
		// Cached tokens are charged at the cached rate instead of regular input rate
		cost -= float64(cachedTokens) * p.InputPerMToken / 1_000_000
		cost += float64(cachedTokens) * p.CachedInputPerMToken / 1_000_000
	}
	return cost
}

// CalculateEmbeddingCost returns the cost for embedding tokens.
func (s *Source) CalculateEmbeddingCost(model string, tokens int) float64 {
	p := s.GetPricing(model)
	if p == nil || p.EmbeddingPerMToken == 0 {
		return 0
	}
	return float64(tokens) * p.EmbeddingPerMToken / 1_000_000
}

// PricingSource returns the source of pricing data for a model.
// Returns "override" if from overrides, "default" if from built-in/file data, "unknown" if not found.
func (s *Source) PricingSource(model string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.overrides != nil {
		if _, ok := s.overrides[model]; ok {
			return "override"
		}
	}
	if _, ok := s.pricing[model]; ok {
		return "default"
	}
	return "unknown"
}

// SetOverride sets a runtime pricing override for a model. Thread-safe.
func (s *Source) SetOverride(model string, pricing *ModelPricing) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.overrides == nil {
		s.overrides = make(map[string]*ModelPricing)
	}
	s.overrides[model] = pricing
}

// RemoveOverride removes a runtime pricing override for a model. Thread-safe.
func (s *Source) RemoveOverride(model string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.overrides, model)
}

// ModelCount returns the number of models with pricing data (base + file-loaded, excluding overrides).
func (s *Source) ModelCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pricing)
}

// liteLLMEntry represents a single model entry in the LiteLLM pricing JSON.
type liteLLMEntry struct {
	InputCostPerToken          *float64 `json:"input_cost_per_token"`
	OutputCostPerToken         *float64 `json:"output_cost_per_token"`
	CacheReadInputTokenCost    *float64 `json:"cache_read_input_token_cost"`
	InputCostPerAudioToken     *float64 `json:"input_cost_per_audio_token"`
	OutputCostPerAudioToken    *float64 `json:"output_cost_per_audio_token"`
	Mode                       string   `json:"mode"`
}

// LoadFile loads model pricing from a LiteLLM-format JSON file.
// Models from the file are merged into the base pricing map. Existing entries
// are overwritten by file data. Overrides still take precedence at lookup time.
func (s *Source) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("pricing: read file: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("pricing: parse file: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	loaded := 0
	for name, msg := range raw {
		if name == "sample_spec" {
			continue
		}

		var entry liteLLMEntry
		if err := json.Unmarshal(msg, &entry); err != nil {
			continue // skip malformed entries
		}

		mp := &ModelPricing{}
		hasData := false

		// Convert per-token cost to per-million-token cost
		if entry.InputCostPerToken != nil && *entry.InputCostPerToken > 0 {
			mp.InputPerMToken = *entry.InputCostPerToken * 1_000_000
			hasData = true
		}
		if entry.OutputCostPerToken != nil && *entry.OutputCostPerToken > 0 {
			mp.OutputPerMToken = *entry.OutputCostPerToken * 1_000_000
			hasData = true
		}
		if entry.CacheReadInputTokenCost != nil && *entry.CacheReadInputTokenCost > 0 {
			mp.CachedInputPerMToken = *entry.CacheReadInputTokenCost * 1_000_000
		}

		// Embedding models use the input cost field
		if entry.Mode == "embedding" && mp.InputPerMToken > 0 {
			mp.EmbeddingPerMToken = mp.InputPerMToken
		}

		if hasData {
			s.pricing[name] = mp
			loaded++
		}
	}

	// Build reverse index: for provider-prefixed keys (e.g. "openai/gpt-4o"),
	// also index by the base model name if that key doesn't already exist.
	// This enables lookup by bare model name for provider-specific entries.
	aliases := 0
	for name, mp := range s.pricing {
		if idx := strings.Index(name, "/"); idx >= 0 {
			base := name[idx+1:]
			if base != "" {
				if _, exists := s.pricing[base]; !exists {
					s.pricing[base] = mp
					aliases++
				}
			}
		}
	}

	slog.Info("pricing file loaded", "path", path, "models_loaded", loaded, "aliases_added", aliases, "total_models", len(s.pricing))
	return nil
}
