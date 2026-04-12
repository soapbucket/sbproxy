// Package circuitbreaker implements the circuit breaker pattern for fault tolerance
package circuitbreaker

import (
	"sync"
	"time"
)

// DefaultConfig provides sensible defaults for circuit breakers wrapping external calls.
var DefaultConfig = Config{
	FailureThreshold: 5,
	SuccessThreshold: 1,
	Timeout:          30 * time.Second,
}

// Registry is a thread-safe collection of named circuit breakers.
// Use GetOrCreate to retrieve an existing breaker or create one on first access.
type Registry struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// GetOrCreate returns the circuit breaker registered under name, creating it
// with the supplied config if it does not yet exist.
func (r *Registry) GetOrCreate(name string, config Config) *CircuitBreaker {
	r.mu.RLock()
	cb, ok := r.breakers[name]
	r.mu.RUnlock()
	if ok {
		return cb
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock.
	if cb, ok = r.breakers[name]; ok {
		return cb
	}

	config.Name = name
	cb = New(config)
	r.breakers[name] = cb
	return cb
}

// Get returns the circuit breaker registered under name, or nil if none exists.
func (r *Registry) Get(name string) *CircuitBreaker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.breakers[name]
}

// DefaultRegistry is the process-wide registry used by all subsystems.
var DefaultRegistry = NewRegistry()
