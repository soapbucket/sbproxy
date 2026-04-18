// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import "sync"

// ModelAliasMap maps friendly model names to provider-specific model IDs.
// It is safe for concurrent use.
type ModelAliasMap struct {
	mu      sync.RWMutex
	aliases map[string]string // alias -> actual model ID
	reverse map[string]string // actual model ID -> alias
}

// NewModelAliasMap creates a ModelAliasMap from the provided alias-to-model mapping.
func NewModelAliasMap(aliases map[string]string) *ModelAliasMap {
	m := &ModelAliasMap{
		aliases: make(map[string]string, len(aliases)),
		reverse: make(map[string]string, len(aliases)),
	}
	for alias, modelID := range aliases {
		m.aliases[alias] = modelID
		m.reverse[modelID] = alias
	}
	return m
}

// Resolve returns the actual model ID for an alias, or the input unchanged if no alias exists.
func (m *ModelAliasMap) Resolve(modelName string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if actual, ok := m.aliases[modelName]; ok {
		return actual
	}
	return modelName
}

// ReverseResolve returns the alias for a model ID, or the input unchanged if no alias exists.
func (m *ModelAliasMap) ReverseResolve(modelID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if alias, ok := m.reverse[modelID]; ok {
		return alias
	}
	return modelID
}

// Add adds or updates an alias mapping.
func (m *ModelAliasMap) Add(alias, modelID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Remove old reverse mapping if this alias previously pointed elsewhere.
	if old, ok := m.aliases[alias]; ok {
		delete(m.reverse, old)
	}
	m.aliases[alias] = modelID
	m.reverse[modelID] = alias
}

// Remove deletes an alias mapping. Returns true if the alias existed.
func (m *ModelAliasMap) Remove(alias string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	modelID, ok := m.aliases[alias]
	if !ok {
		return false
	}
	delete(m.aliases, alias)
	delete(m.reverse, modelID)
	return true
}

// List returns a copy of all alias mappings.
func (m *ModelAliasMap) List() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make(map[string]string, len(m.aliases))
	for k, v := range m.aliases {
		cp[k] = v
	}
	return cp
}
