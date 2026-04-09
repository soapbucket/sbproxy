package wasm

import (
	"context"
	"fmt"
)

// ModuleExports records which lifecycle hooks the module exports.
type ModuleExports struct {
	HasOnConfig   bool
	HasOnRequest  bool
	HasOnResponse bool
	HasMalloc     bool
}

// CompiledModule wraps a compiled WASM module with export validation.
type CompiledModule struct {
	compiled CompiledWasmModule
	name     string
	exports  ModuleExports
}

// Compile compiles a WASM binary and validates its exports.
func (r *Runtime) Compile(ctx context.Context, name string, wasmBytes []byte) (*CompiledModule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.engine == nil {
		return nil, fmt.Errorf("wasm runtime is closed")
	}

	if name == "" {
		return nil, fmt.Errorf("module name is required")
	}

	if len(wasmBytes) == 0 {
		return nil, fmt.Errorf("wasm bytes are empty")
	}

	compiled, err := r.engine.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compile module %q: %w", name, err)
	}

	// Inspect exported functions to populate ModuleExports.
	exports := ModuleExports{}
	for _, def := range compiled.ExportedFunctions() {
		fname := def.ExportNames()[0]
		switch fname {
		case "sb_on_config":
			exports.HasOnConfig = true
		case "sb_on_request":
			exports.HasOnRequest = true
		case "sb_on_response":
			exports.HasOnResponse = true
		case "sb_malloc":
			exports.HasMalloc = true
		}
	}

	cm := &CompiledModule{
		compiled: compiled,
		name:     name,
		exports:  exports,
	}

	if err := cm.ValidateExports(); err != nil {
		compiled.Close(ctx)
		return nil, err
	}

	return cm, nil
}

// ValidateExports checks that the module has at least one lifecycle hook
// and has sb_malloc for memory allocation.
func (cm *CompiledModule) ValidateExports() error {
	if !cm.exports.HasOnRequest && !cm.exports.HasOnResponse {
		return fmt.Errorf("module %q must export at least one of sb_on_request or sb_on_response", cm.name)
	}
	if !cm.exports.HasMalloc {
		return fmt.Errorf("module %q must export sb_malloc for host-to-guest data passing", cm.name)
	}
	return nil
}

// Exports returns the module's export information.
func (cm *CompiledModule) Exports() ModuleExports {
	return cm.exports
}

// Name returns the compiled module name.
func (cm *CompiledModule) Name() string {
	return cm.name
}

// Close releases the compiled module resources.
func (cm *CompiledModule) Close(ctx context.Context) error {
	if cm.compiled != nil {
		return cm.compiled.Close(ctx)
	}
	return nil
}
