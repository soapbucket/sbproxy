package wasm

import "context"

// WasmEngine abstracts the WASM runtime engine (e.g., wazero.Runtime).
// In the core build this interface has no concrete implementation;
// NewRuntime returns ErrNotAvailable.
type WasmEngine interface {
	NewHostModuleBuilder(name string) HostModuleBuilder
	CompileModule(ctx context.Context, wasmBytes []byte) (CompiledWasmModule, error)
	InstantiateModule(ctx context.Context, compiled CompiledWasmModule, cfg WasmModuleConfig) (WasmModule, error)
	Close(ctx context.Context) error
}

// HostModuleBuilder abstracts the host module builder (e.g., wazero.HostModuleBuilder).
type HostModuleBuilder interface {
	NewFunctionBuilder() FunctionBuilder
	Instantiate(ctx context.Context) (WasmModule, error)
}

// FunctionBuilder abstracts the function builder used to register host functions.
type FunctionBuilder interface {
	WithGoModuleFunction(fn GoModuleFunc, params []ValueType, results []ValueType) FunctionBuilder
	WithParameterNames(names ...string) FunctionBuilder
	Export(name string) HostModuleBuilder
}

// GoModuleFunc is the callback signature for host functions.
type GoModuleFunc func(ctx context.Context, mod WasmModule, stack []uint64)

// CompiledWasmModule abstracts a compiled WASM module.
type CompiledWasmModule interface {
	ExportedFunctions() []ExportedFunctionDef
	Close(ctx context.Context) error
}

// ExportedFunctionDef describes an exported function.
type ExportedFunctionDef interface {
	ExportNames() []string
}

// WasmModule abstracts an instantiated WASM module (e.g., api.Module).
type WasmModule interface {
	ExportedFunction(name string) WasmFunction
	Memory() WasmMemory
	Close(ctx context.Context) error
}

// WasmFunction abstracts a callable WASM function.
type WasmFunction interface {
	Call(ctx context.Context, params ...uint64) ([]uint64, error)
}

// WasmMemory abstracts WASM linear memory.
type WasmMemory interface {
	Read(offset uint32, byteCount uint32) ([]byte, bool)
	Write(offset uint32, val []byte) bool
	Size() uint32
}

// WasmModuleConfig abstracts module configuration (e.g., wazero.ModuleConfig).
type WasmModuleConfig interface{}

// ValueType represents a WASM value type.
type ValueType byte

const (
	// ValueTypeI32 represents a 32-bit integer.
	ValueTypeI32 ValueType = 0x7F
	// ValueTypeI64 represents a 64-bit integer.
	ValueTypeI64 ValueType = 0x7E
)

// NewModuleConfig creates a new module configuration.
// In the core build this returns a stub config.
func NewModuleConfig() moduleConfigBuilder {
	return moduleConfigBuilder{}
}

type moduleConfigBuilder struct {
	name string
}

// WithName sets the module name.
func (b moduleConfigBuilder) WithName(name string) WasmModuleConfig {
	b.name = name
	return b
}
