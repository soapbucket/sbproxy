// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	json "github.com/goccy/go-json"
	"fmt"
	"sync"
)

// ConstructorFn creates a Guardrail from JSON config.
type ConstructorFn func(config json.RawMessage) (Guardrail, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]ConstructorFn{}
)

// Register adds a guardrail constructor to the registry.
func Register(name string, fn ConstructorFn) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = fn
}

// Create instantiates a guardrail by type name with the given config.
func Create(name string, config json.RawMessage) (Guardrail, error) {
	registryMu.RLock()
	fn, ok := registry[name]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown guardrail type: %s", name)
	}
	return fn(config)
}

// RegisteredTypes returns all registered guardrail type names.
func RegisteredTypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	types := make([]string, 0, len(registry))
	for name := range registry {
		types = append(types, name)
	}
	return types
}
