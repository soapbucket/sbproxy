// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"path"
	"sort"
	"sync"
)

// ModelRegistryEntry maps a model pattern to a provider with routing metadata.
type ModelRegistryEntry struct {
	// ModelPattern is an exact model name or glob pattern (e.g., "gpt-4*").
	ModelPattern string `json:"model_pattern"`
	// Provider is the name of the target provider.
	Provider string `json:"provider"`
	// Priority controls selection order (lower wins).
	Priority int `json:"priority"`
	// ModelOverride optionally remaps the model name sent to the provider.
	ModelOverride string `json:"model_override,omitempty"`
	// Reserved marks this entry as reserved capacity (tried first before on-demand).
	Reserved bool `json:"reserved,omitempty"`
}

// ModelRegistry holds a sorted set of model-to-provider mappings and provides
// thread-safe lookup by exact name or glob pattern.
type ModelRegistry struct {
	mu      sync.RWMutex
	entries []ModelRegistryEntry // sorted by Priority ascending
}

// NewModelRegistry creates a ModelRegistry from the given entries, sorted by priority.
func NewModelRegistry(entries []ModelRegistryEntry) *ModelRegistry {
	sorted := make([]ModelRegistryEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	return &ModelRegistry{entries: sorted}
}

// Lookup returns the best-matching provider for the given model name.
// It tries exact match first, then glob patterns, returning the first hit by priority.
func (mr *ModelRegistry) Lookup(model string) (provider string, modelOverride string, found bool) {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	// First pass: exact match (higher precedence than glob).
	for _, e := range mr.entries {
		if e.ModelPattern == model {
			return e.Provider, e.ModelOverride, true
		}
	}

	// Second pass: glob pattern match.
	for _, e := range mr.entries {
		if matched, _ := path.Match(e.ModelPattern, model); matched {
			return e.Provider, e.ModelOverride, true
		}
	}

	return "", "", false
}

// LookupAll returns every matching entry for the given model, sorted by priority.
// This is used for fallback and capacity routing.
func (mr *ModelRegistry) LookupAll(model string) []ModelRegistryEntry {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	var results []ModelRegistryEntry
	for _, e := range mr.entries {
		if e.ModelPattern == model {
			results = append(results, e)
			continue
		}
		if matched, _ := path.Match(e.ModelPattern, model); matched {
			results = append(results, e)
		}
	}
	return results
}

// Models returns all registered model patterns.
func (mr *ModelRegistry) Models() []string {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	patterns := make([]string, len(mr.entries))
	for i, e := range mr.entries {
		patterns[i] = e.ModelPattern
	}
	return patterns
}

// AddEntry inserts an entry into the registry, maintaining priority order.
func (mr *ModelRegistry) AddEntry(entry ModelRegistryEntry) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	// Find insertion point via binary search on Priority.
	idx := sort.Search(len(mr.entries), func(i int) bool {
		return mr.entries[i].Priority >= entry.Priority
	})
	// Insert at idx.
	mr.entries = append(mr.entries, ModelRegistryEntry{})
	copy(mr.entries[idx+1:], mr.entries[idx:])
	mr.entries[idx] = entry
}

// RemoveEntry removes all entries whose ModelPattern matches the given pattern.
func (mr *ModelRegistry) RemoveEntry(pattern string) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	n := 0
	for _, e := range mr.entries {
		if e.ModelPattern != pattern {
			mr.entries[n] = e
			n++
		}
	}
	mr.entries = mr.entries[:n]
}
