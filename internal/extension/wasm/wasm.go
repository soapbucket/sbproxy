// Package wasm provides a WASM plugin runtime stub.
//
// In the open-source build, WASM support is not available. NewRuntime returns
// ErrNotAvailable. All types are defined so callers can compile, but no
// concrete implementation is provided.
package wasm

import (
	"context"
	"fmt"
)

// ErrNotAvailable is returned when WASM support is not compiled in.
var ErrNotAvailable = fmt.Errorf("wasm: runtime not available in this build")

// Runtime manages WASM module compilation and execution.
// In the open-source build, NewRuntime always returns ErrNotAvailable.
type Runtime struct{}

// NewRuntime always returns ErrNotAvailable in the open-source build.
func NewRuntime(_ context.Context, _ RuntimeConfig) (*Runtime, error) {
	return nil, ErrNotAvailable
}

// Close is a no-op.
func (r *Runtime) Close(_ context.Context) error { return nil }

// RuntimeConfig configures the WASM runtime.
type RuntimeConfig struct {
	MaxMemoryMB int `json:"max_memory_mb,omitempty"`
}
