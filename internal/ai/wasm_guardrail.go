package ai

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
	"github.com/soapbucket/sbproxy/internal/extension/wasm"
)

// WASMGuardrailConfig configures a WASM-based guardrail detector.
type WASMGuardrailConfig struct {
	ModulePath       string        `json:"module_path"`
	SHA256           string        `json:"sha256,omitempty"`
	Timeout          time.Duration `json:"timeout,omitempty"`
	MemoryLimitPages uint32        `json:"memory_limit_pages,omitempty"` // Each page is 64KB
}

// Validate checks the configuration for required fields.
func (c *WASMGuardrailConfig) Validate() error {
	if c.ModulePath == "" {
		return fmt.Errorf("wasm guardrail: module_path is required")
	}
	return nil
}

// WASMGuardrail implements the policy.GuardrailDetector interface using a WASM module.
type WASMGuardrail struct {
	config  WASMGuardrailConfig
	runtime *wasm.Runtime
	module  []byte // Cached WASM bytes
}

// Ensure WASMGuardrail implements GuardrailDetector at compile time.
var _ policy.GuardrailDetector = (*WASMGuardrail)(nil)

// NewWASMGuardrail creates a new WASM guardrail detector.
func NewWASMGuardrail(cfg WASMGuardrailConfig, rt *wasm.Runtime) (*WASMGuardrail, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if rt == nil {
		return nil, fmt.Errorf("wasm guardrail: runtime is required")
	}

	wasmBytes, err := os.ReadFile(cfg.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("wasm guardrail: failed to read module %q: %w", cfg.ModulePath, err)
	}

	if cfg.SHA256 != "" {
		if err := wasm.VerifyIntegrity(wasmBytes, cfg.SHA256); err != nil {
			return nil, fmt.Errorf("wasm guardrail: %w", err)
		}
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = 100 * time.Millisecond
	}

	return &WASMGuardrail{
		config:  cfg,
		runtime: rt,
		module:  wasmBytes,
	}, nil
}

// Detect runs the WASM guardrail check on the given content.
func (wg *WASMGuardrail) Detect(ctx context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()

	result := &policy.GuardrailResult{
		GuardrailID: config.ID,
		Name:        config.Name,
		Action:      config.Action,
	}

	execCtx, cancel := context.WithTimeout(ctx, wg.config.Timeout)
	defer cancel()

	action, err := wg.executeCheck(execCtx, content)
	if err != nil {
		result.Latency = time.Since(start)
		return nil, fmt.Errorf("wasm guardrail %q: %w", config.ID, err)
	}

	result.Latency = time.Since(start)

	switch action {
	case 0:
		result.Triggered = false
	case 1:
		result.Triggered = true
		result.Action = policy.GuardrailActionBlock
		result.Details = "WASM module returned block action"
	case 2:
		result.Triggered = true
		result.Action = policy.GuardrailActionFlag
		result.Details = "WASM module returned flag action"
	case 3:
		result.Triggered = true
		result.Action = policy.GuardrailActionRedact
		result.Details = "WASM module returned redact action"
	default:
		result.Triggered = false
	}

	return result, nil
}

// executeCheck compiles the module, instantiates it, writes content, and calls check.
func (wg *WASMGuardrail) executeCheck(ctx context.Context, content string) (int32, error) {
	engine, err := wg.runtime.Engine()
	if err != nil {
		return 0, fmt.Errorf("runtime unavailable: %w", err)
	}

	// Register host functions (including AI host functions).
	hostModule := engine.NewHostModuleBuilder("sb")
	wasm.RegisterHostFunctions(hostModule)
	wasm.RegisterAIHostFunctions(hostModule)
	if _, err := hostModule.Instantiate(ctx); err != nil {
		if !strings.Contains(err.Error(), "has already been instantiated") {
			return 0, fmt.Errorf("failed to instantiate host module: %w", err)
		}
	}

	compiled, err := engine.CompileModule(ctx, wg.module)
	if err != nil {
		return 0, fmt.Errorf("compile failed: %w", err)
	}
	defer compiled.Close(ctx)

	moduleCfg := wasm.NewModuleConfig().WithName("")
	module, err := engine.InstantiateModule(ctx, compiled, moduleCfg)
	if err != nil {
		return 0, fmt.Errorf("instantiate failed: %w", err)
	}
	defer module.Close(ctx)

	checkFn := module.ExportedFunction("check")
	if checkFn == nil {
		return 0, fmt.Errorf("module does not export 'check' function")
	}

	// Write content to guest memory via sb_malloc.
	ptr, length := wasm.WriteBytes(ctx, module, []byte(content))
	if len(content) > 0 && ptr == 0 {
		return 0, fmt.Errorf("failed to write content to guest memory")
	}

	results, err := checkFn.Call(ctx, uint64(ptr), uint64(length))
	if err != nil {
		return 0, fmt.Errorf("check call failed: %w", err)
	}

	if len(results) == 0 {
		return 0, nil
	}

	return int32(results[0]), nil
}
