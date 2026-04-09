package ai

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/extension/wasm"
)

// WASMCompressorConfig configures a WASM-based compression plugin.
type WASMCompressorConfig struct {
	ModulePath string        `json:"module_path"`
	SHA256     string        `json:"sha256,omitempty"`
	Timeout    time.Duration `json:"timeout,omitempty"`
}

// Validate checks the configuration for required fields.
func (c *WASMCompressorConfig) Validate() error {
	if c.ModulePath == "" {
		return fmt.Errorf("wasm compressor: module_path is required")
	}
	return nil
}

// WASMCompressor applies WASM-based compression to data.
type WASMCompressor struct {
	config  WASMCompressorConfig
	runtime *wasm.Runtime
	module  []byte // Cached WASM bytes
}

// NewWASMCompressor creates a new WASM-based compressor.
func NewWASMCompressor(cfg WASMCompressorConfig, rt *wasm.Runtime) (*WASMCompressor, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if rt == nil {
		return nil, fmt.Errorf("wasm compressor: runtime is required")
	}

	wasmBytes, err := os.ReadFile(cfg.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("wasm compressor: failed to read module %q: %w", cfg.ModulePath, err)
	}

	if cfg.SHA256 != "" {
		if err := wasm.VerifyIntegrity(wasmBytes, cfg.SHA256); err != nil {
			return nil, fmt.Errorf("wasm compressor: %w", err)
		}
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 100 * time.Millisecond
	}

	return &WASMCompressor{
		config:  cfg,
		runtime: rt,
		module:  wasmBytes,
	}, nil
}

// Compress applies the WASM compression to the input data.
func (wc *WASMCompressor) Compress(ctx context.Context, input []byte) ([]byte, error) {
	execCtx, cancel := context.WithTimeout(ctx, wc.config.Timeout)
	defer cancel()

	return wc.executeCompress(execCtx, input)
}

// executeCompress compiles the module, instantiates it, and calls the compress function.
func (wc *WASMCompressor) executeCompress(ctx context.Context, input []byte) ([]byte, error) {
	engine, err := wc.runtime.Engine()
	if err != nil {
		return nil, fmt.Errorf("runtime unavailable: %w", err)
	}

	// Register host functions.
	hostModule := engine.NewHostModuleBuilder("sb")
	wasm.RegisterHostFunctions(hostModule)
	wasm.RegisterAIHostFunctions(hostModule)
	if _, err := hostModule.Instantiate(ctx); err != nil {
		if !strings.Contains(err.Error(), "has already been instantiated") {
			return nil, fmt.Errorf("failed to instantiate host module: %w", err)
		}
	}

	compiled, err := engine.CompileModule(ctx, wc.module)
	if err != nil {
		return nil, fmt.Errorf("compile failed: %w", err)
	}
	defer compiled.Close(ctx)

	moduleCfg := wasm.NewModuleConfig().WithName("")
	module, err := engine.InstantiateModule(ctx, compiled, moduleCfg)
	if err != nil {
		return nil, fmt.Errorf("instantiate failed: %w", err)
	}
	defer module.Close(ctx)

	fn := module.ExportedFunction("compress")
	if fn == nil {
		return nil, fmt.Errorf("module does not export 'compress' function")
	}

	// Write input to guest memory.
	ptr, length := wasm.WriteBytes(ctx, module, input)
	if len(input) > 0 && ptr == 0 {
		return nil, fmt.Errorf("failed to write input to guest memory")
	}

	results, err := fn.Call(ctx, uint64(ptr), uint64(length))
	if err != nil {
		return nil, fmt.Errorf("compress call failed: %w", err)
	}

	if len(results) < 2 {
		return nil, fmt.Errorf("compress returned insufficient values (expected ptr, len)")
	}

	outPtr := uint32(results[0])
	outLen := uint32(results[1])
	if outLen == 0 {
		return nil, nil
	}

	output := wasm.ReadBytes(module, outPtr, outLen)
	if output == nil {
		return nil, fmt.Errorf("failed to read compressed output from guest memory")
	}

	return output, nil
}
