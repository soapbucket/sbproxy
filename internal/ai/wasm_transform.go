package ai

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/extension/wasm"
)

// WASMTransformPhase defines when the transform runs.
type WASMTransformPhase string

const (
	// WASMTransformPhasePre runs before forwarding to the upstream provider.
	WASMTransformPhasePre WASMTransformPhase = "pre"
	// WASMTransformPhasePost runs after receiving the response from the upstream provider.
	WASMTransformPhasePost WASMTransformPhase = "post"
)

// WASMTransformConfig configures a WASM-based request/response transformer.
type WASMTransformConfig struct {
	ModulePath string             `json:"module_path"`
	Phase      WASMTransformPhase `json:"phase"` // "pre" or "post"
	SHA256     string             `json:"sha256,omitempty"`
	Timeout    time.Duration      `json:"timeout,omitempty"`
}

// Validate checks the configuration for required fields.
func (c *WASMTransformConfig) Validate() error {
	if c.ModulePath == "" {
		return fmt.Errorf("wasm transform: module_path is required")
	}
	if c.Phase != WASMTransformPhasePre && c.Phase != WASMTransformPhasePost {
		return fmt.Errorf("wasm transform: phase must be %q or %q, got %q", WASMTransformPhasePre, WASMTransformPhasePost, c.Phase)
	}
	return nil
}

// WASMTransform applies WASM-based request or response transformations.
type WASMTransform struct {
	config  WASMTransformConfig
	runtime *wasm.Runtime
	module  []byte // Cached WASM bytes
}

// NewWASMTransform creates a new WASM transform.
func NewWASMTransform(cfg WASMTransformConfig, rt *wasm.Runtime) (*WASMTransform, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if rt == nil {
		return nil, fmt.Errorf("wasm transform: runtime is required")
	}

	wasmBytes, err := os.ReadFile(cfg.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("wasm transform: failed to read module %q: %w", cfg.ModulePath, err)
	}

	if cfg.SHA256 != "" {
		if err := wasm.VerifyIntegrity(wasmBytes, cfg.SHA256); err != nil {
			return nil, fmt.Errorf("wasm transform: %w", err)
		}
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 100 * time.Millisecond
	}

	return &WASMTransform{
		config:  cfg,
		runtime: rt,
		module:  wasmBytes,
	}, nil
}

// Transform applies the WASM transform to the input data.
func (wt *WASMTransform) Transform(ctx context.Context, input []byte) ([]byte, error) {
	execCtx, cancel := context.WithTimeout(ctx, wt.config.Timeout)
	defer cancel()

	var exportName string
	switch wt.config.Phase {
	case WASMTransformPhasePre:
		exportName = "transform_request"
	case WASMTransformPhasePost:
		exportName = "transform_response"
	default:
		return nil, fmt.Errorf("wasm transform: invalid phase %q", wt.config.Phase)
	}

	return wt.executeTransform(execCtx, exportName, input)
}

// Phase returns the configured transform phase.
func (wt *WASMTransform) Phase() WASMTransformPhase {
	return wt.config.Phase
}

// executeTransform compiles the module, instantiates it, and calls the transform function.
func (wt *WASMTransform) executeTransform(ctx context.Context, exportName string, input []byte) ([]byte, error) {
	engine, err := wt.runtime.Engine()
	if err != nil {
		return nil, fmt.Errorf("runtime unavailable: %w", err)
	}

	// Register host functions (including AI host functions).
	hostModule := engine.NewHostModuleBuilder("sb")
	wasm.RegisterHostFunctions(hostModule)
	wasm.RegisterAIHostFunctions(hostModule)
	if _, err := hostModule.Instantiate(ctx); err != nil {
		if !strings.Contains(err.Error(), "has already been instantiated") {
			return nil, fmt.Errorf("failed to instantiate host module: %w", err)
		}
	}

	compiled, err := engine.CompileModule(ctx, wt.module)
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

	fn := module.ExportedFunction(exportName)
	if fn == nil {
		return nil, fmt.Errorf("module does not export %q function", exportName)
	}

	// Write input to guest memory.
	ptr, length := wasm.WriteBytes(ctx, module, input)
	if len(input) > 0 && ptr == 0 {
		return nil, fmt.Errorf("failed to write input to guest memory")
	}

	results, err := fn.Call(ctx, uint64(ptr), uint64(length))
	if err != nil {
		return nil, fmt.Errorf("%s call failed: %w", exportName, err)
	}

	if len(results) < 2 {
		return nil, fmt.Errorf("%s returned insufficient values (expected ptr, len)", exportName)
	}

	outPtr := uint32(results[0])
	outLen := uint32(results[1])
	if outLen == 0 {
		return nil, nil
	}

	output := wasm.ReadBytes(module, outPtr, outLen)
	if output == nil {
		return nil, fmt.Errorf("failed to read transform output from guest memory")
	}

	return output, nil
}
