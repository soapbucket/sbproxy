// Package wasm provides a WASM plugin runtime for the SoapBucket proxy.
//
// In the core build, WASM support is not available. NewRuntime returns
// ErrNotAvailable. The enterprise build provides a concrete implementation
// backed by a WASM engine.
package wasm

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	defaultMaxMemoryMB     = 16
	defaultMaxExecDuration = 100 * time.Millisecond
)

// ErrNotAvailable is returned when WASM support is not compiled in.
var ErrNotAvailable = fmt.Errorf("wasm: runtime not available in core build (requires enterprise dependency)")

// RuntimeConfig configures the WASM runtime.
type RuntimeConfig struct {
	MaxMemoryMB     int           `json:"max_memory_mb,omitempty"`     // Default: 16
	MaxExecDuration time.Duration `json:"max_exec_duration,omitempty"` // Default: 100ms
}

// applyDefaults fills in zero-valued fields with defaults.
func (c *RuntimeConfig) applyDefaults() {
	if c.MaxMemoryMB <= 0 {
		c.MaxMemoryMB = defaultMaxMemoryMB
	}
	if c.MaxExecDuration <= 0 {
		c.MaxExecDuration = defaultMaxExecDuration
	}
}

// Runtime manages WASM module compilation and execution.
type Runtime struct {
	engine   WasmEngine
	config   RuntimeConfig
	registry ModuleRegistry
	mu       sync.RWMutex
}

// SetRegistry sets the module registry used for registry: and system: path resolution.
func (r *Runtime) SetRegistry(reg ModuleRegistry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registry = reg
}

// Registry returns the configured module registry, or nil if none is set.
func (r *Runtime) Registry() ModuleRegistry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.registry
}

// NewRuntime creates a new WASM runtime with the given configuration.
// In the core build this always returns ErrNotAvailable.
func NewRuntime(_ context.Context, _ RuntimeConfig) (*Runtime, error) {
	return nil, ErrNotAvailable
}

// Close releases all resources held by the runtime.
func (r *Runtime) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.engine == nil {
		return nil
	}
	err := r.engine.Close(ctx)
	r.engine = nil
	return err
}

// Config returns the runtime configuration.
func (r *Runtime) Config() RuntimeConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.config
}

// Engine returns the underlying WASM engine. Returns an error if the runtime is closed.
func (r *Runtime) Engine() (WasmEngine, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.engine == nil {
		return nil, fmt.Errorf("wasm runtime is closed")
	}
	return r.engine, nil
}
