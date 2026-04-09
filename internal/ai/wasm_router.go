package ai

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/extension/wasm"
)

// WASMRouterConfig configures a WASM-based routing plugin.
type WASMRouterConfig struct {
	ModulePath string        `json:"module_path"`
	SHA256     string        `json:"sha256,omitempty"`
	Timeout    time.Duration `json:"timeout,omitempty"`
}

// Validate checks the configuration for required fields.
func (c *WASMRouterConfig) Validate() error {
	if c.ModulePath == "" {
		return fmt.Errorf("wasm router: module_path is required")
	}
	return nil
}

// wasmRouteInput is the JSON payload sent to the WASM select_provider function.
type wasmRouteInput struct {
	Model     string   `json:"model"`
	Providers []string `json:"providers"`
}

// WASMRouter selects an AI provider using a WASM module.
// The WASM module must export a `select_provider(ptr, len) -> (ptr, len)` function
// that accepts a JSON payload with model and available providers and returns
// the selected provider name as a string.
type WASMRouter struct {
	config  WASMRouterConfig
	runtime *wasm.Runtime
	module  []byte // Cached WASM bytes
}

// NewWASMRouter creates a new WASM-based router.
// It loads the WASM module bytes and verifies integrity if a SHA256 hash is provided.
func NewWASMRouter(cfg WASMRouterConfig, rt *wasm.Runtime) (*WASMRouter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if rt == nil {
		return nil, fmt.Errorf("wasm router: runtime is required")
	}

	wasmBytes, err := os.ReadFile(cfg.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("wasm router: failed to read module %q: %w", cfg.ModulePath, err)
	}

	if cfg.SHA256 != "" {
		if err := wasm.VerifyIntegrity(wasmBytes, cfg.SHA256); err != nil {
			return nil, fmt.Errorf("wasm router: %w", err)
		}
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 100 * time.Millisecond
	}

	return &WASMRouter{
		config:  cfg,
		runtime: rt,
		module:  wasmBytes,
	}, nil
}

// Route calls the WASM module to select a provider for the given model and available providers.
func (wr *WASMRouter) Route(ctx context.Context, model string, providers []string) (string, error) {
	execCtx, cancel := context.WithTimeout(ctx, wr.config.Timeout)
	defer cancel()

	return wr.executeRoute(execCtx, model, providers)
}

// executeRoute compiles the module, instantiates it, and calls select_provider.
func (wr *WASMRouter) executeRoute(ctx context.Context, model string, providers []string) (string, error) {
	engine, err := wr.runtime.Engine()
	if err != nil {
		return "", fmt.Errorf("runtime unavailable: %w", err)
	}

	// Register host functions.
	// Ignore "already instantiated" errors since host modules persist per runtime.
	hostModule := engine.NewHostModuleBuilder("sb")
	wasm.RegisterHostFunctions(hostModule)
	wasm.RegisterAIHostFunctions(hostModule)
	if _, err := hostModule.Instantiate(ctx); err != nil {
		if !strings.Contains(err.Error(), "has already been instantiated") {
			return "", fmt.Errorf("failed to instantiate host module: %w", err)
		}
	}

	compiled, err := engine.CompileModule(ctx, wr.module)
	if err != nil {
		return "", fmt.Errorf("compile failed: %w", err)
	}
	defer compiled.Close(ctx)

	moduleCfg := wasm.NewModuleConfig().WithName("")
	module, err := engine.InstantiateModule(ctx, compiled, moduleCfg)
	if err != nil {
		return "", fmt.Errorf("instantiate failed: %w", err)
	}
	defer module.Close(ctx)

	fn := module.ExportedFunction("select_provider")
	if fn == nil {
		return "", fmt.Errorf("module does not export 'select_provider' function")
	}

	// Build JSON input.
	input := wasmRouteInput{
		Model:     model,
		Providers: providers,
	}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("failed to marshal route input: %w", err)
	}

	// Write input to guest memory.
	ptr, length := wasm.WriteBytes(ctx, module, inputBytes)
	if ptr == 0 && len(inputBytes) > 0 {
		return "", fmt.Errorf("failed to write input to guest memory")
	}

	results, err := fn.Call(ctx, uint64(ptr), uint64(length))
	if err != nil {
		return "", fmt.Errorf("select_provider call failed: %w", err)
	}

	if len(results) < 2 {
		return "", fmt.Errorf("select_provider returned insufficient values (expected ptr, len)")
	}

	outPtr := uint32(results[0])
	outLen := uint32(results[1])
	if outLen == 0 {
		return "", fmt.Errorf("select_provider returned empty result")
	}

	output := wasm.ReadString(module, outPtr, outLen)
	if output == "" {
		return "", fmt.Errorf("failed to read provider name from guest memory")
	}

	return output, nil
}
