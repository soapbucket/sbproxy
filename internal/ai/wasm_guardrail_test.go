package ai

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
	"github.com/soapbucket/sbproxy/internal/extension/wasm"
)

func TestWASMGuardrailConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     WASMGuardrailConfig
		wantErr bool
	}{
		{
			name:    "empty module path",
			cfg:     WASMGuardrailConfig{},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: WASMGuardrailConfig{
				ModulePath: "/path/to/module.wasm",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewWASMGuardrail_Errors(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	t.Run("nil runtime", func(t *testing.T) {
		_, err := NewWASMGuardrail(WASMGuardrailConfig{ModulePath: "/tmp/test.wasm"}, nil)
		if err == nil {
			t.Error("expected error for nil runtime")
		}
	})

	t.Run("empty module path", func(t *testing.T) {
		_, err := NewWASMGuardrail(WASMGuardrailConfig{}, rt)
		if err == nil {
			t.Error("expected error for empty module path")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := NewWASMGuardrail(WASMGuardrailConfig{ModulePath: "/nonexistent/module.wasm"}, rt)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("sha256 mismatch", func(t *testing.T) {
		// Create a temp file with dummy content.
		tmpDir := t.TempDir()
		wasmPath := filepath.Join(tmpDir, "test.wasm")
		if err := os.WriteFile(wasmPath, []byte("not real wasm"), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		_, err := NewWASMGuardrail(WASMGuardrailConfig{
			ModulePath: wasmPath,
			SHA256:     "0000000000000000000000000000000000000000000000000000000000000000",
		}, rt)
		if err == nil {
			t.Error("expected error for SHA256 mismatch")
		}
	})

	t.Run("default timeout applied", func(t *testing.T) {
		tmpDir := t.TempDir()
		wasmPath := filepath.Join(tmpDir, "test.wasm")
		if err := os.WriteFile(wasmPath, []byte("fake wasm content"), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		wg, err := NewWASMGuardrail(WASMGuardrailConfig{ModulePath: wasmPath}, rt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wg.config.Timeout != 100*time.Millisecond {
			t.Errorf("default timeout = %v, want %v", wg.config.Timeout, 100*time.Millisecond)
		}
	})
}

func TestWASMGuardrail_InterfaceCompliance(t *testing.T) {
	// Verify WASMGuardrail implements GuardrailDetector at compile time.
	var _ policy.GuardrailDetector = (*WASMGuardrail)(nil)
}

func TestWASMGuardrail_Detect_WithRealWASM(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	// Build a minimal WASM module in memory that exports `check` returning 1 (block)
	// and `sb_malloc` for memory allocation.
	// This is a valid WASM binary built from WAT:
	// (module
	//   (memory (export "memory") 1)
	//   (func (export "sb_malloc") (param i32) (result i32) i32.const 0)
	//   (func (export "check") (param i32 i32) (result i32) i32.const 1)
	// )
	wasmBytes := buildTestGuardrailModule(1) // returns action=1 (block)

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "guardrail.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
		t.Fatalf("failed to write wasm: %v", err)
	}

	wg, err := NewWASMGuardrail(WASMGuardrailConfig{ModulePath: wasmPath}, rt)
	if err != nil {
		t.Fatalf("NewWASMGuardrail: %v", err)
	}

	config := &policy.GuardrailConfig{
		ID:     "test-guardrail",
		Name:   "Test WASM Guardrail",
		Action: policy.GuardrailActionBlock,
	}

	result, err := wg.Detect(ctx, config, "test content")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if !result.Triggered {
		t.Error("expected guardrail to be triggered")
	}
	if result.Action != policy.GuardrailActionBlock {
		t.Errorf("action = %v, want %v", result.Action, policy.GuardrailActionBlock)
	}
	if result.GuardrailID != "test-guardrail" {
		t.Errorf("guardrail_id = %q, want %q", result.GuardrailID, "test-guardrail")
	}
}

func TestWASMGuardrail_Detect_Pass(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	wasmBytes := buildTestGuardrailModule(0) // returns action=0 (pass)

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "guardrail_pass.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
		t.Fatalf("failed to write wasm: %v", err)
	}

	wg, err := NewWASMGuardrail(WASMGuardrailConfig{ModulePath: wasmPath}, rt)
	if err != nil {
		t.Fatalf("NewWASMGuardrail: %v", err)
	}

	config := &policy.GuardrailConfig{
		ID:     "pass-guardrail",
		Name:   "Pass Guardrail",
		Action: policy.GuardrailActionBlock,
	}

	result, err := wg.Detect(ctx, config, "safe content")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if result.Triggered {
		t.Error("expected guardrail not to be triggered for pass action")
	}
}

func TestWASMGuardrail_Detect_AllActions(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	tests := []struct {
		name       string
		returnCode int
		triggered  bool
		wantAction policy.GuardrailAction
	}{
		{"pass", 0, false, policy.GuardrailActionBlock},  // default from config, not triggered
		{"block", 1, true, policy.GuardrailActionBlock},
		{"flag", 2, true, policy.GuardrailActionFlag},
		{"redact", 3, true, policy.GuardrailActionRedact},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wasmBytes := buildTestGuardrailModule(tt.returnCode)
			tmpDir := t.TempDir()
			wasmPath := filepath.Join(tmpDir, "guardrail.wasm")
			if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
				t.Fatalf("failed to write wasm: %v", err)
			}

			wg, err := NewWASMGuardrail(WASMGuardrailConfig{ModulePath: wasmPath}, rt)
			if err != nil {
				t.Fatalf("NewWASMGuardrail: %v", err)
			}

			config := &policy.GuardrailConfig{
				ID:     "test-" + tt.name,
				Name:   "Test " + tt.name,
				Action: policy.GuardrailActionBlock,
			}

			result, err := wg.Detect(ctx, config, "test")
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}

			if result.Triggered != tt.triggered {
				t.Errorf("triggered = %v, want %v", result.Triggered, tt.triggered)
			}
			if tt.triggered && result.Action != tt.wantAction {
				t.Errorf("action = %v, want %v", result.Action, tt.wantAction)
			}
		})
	}
}

// buildTestGuardrailModule creates a minimal WASM module that exports:
// - memory
// - sb_malloc(size i32) -> i32 (always returns 0, sufficient for tests where we read but ignore input)
// - check(ptr i32, len i32) -> i32 (returns the given returnCode)
func buildTestGuardrailModule(returnCode int) []byte {
	// This is a hand-crafted minimal valid WASM binary.
	// WAT equivalent:
	// (module
	//   (memory (export "memory") 1)
	//   (func (export "sb_malloc") (param i32) (result i32) i32.const 1024)
	//   (func (export "check") (param i32 i32) (result i32) i32.const <returnCode>)
	// )
	return buildWASMModule([]wasmExport{
		{name: "sb_malloc", params: 1, results: 1, body: []byte{0x41, 0x80, 0x08}},       // i32.const 1024
		{name: "check", params: 2, results: 1, body: encodeI32Const(returnCode)},
	})
}

// wasmExport describes a function to export from a test WASM module.
type wasmExport struct {
	name    string
	params  int // number of i32 params
	results int // number of i32 results
	body    []byte // function body (wasm instructions, without end byte)
}

// buildWASMModule constructs a minimal valid WASM binary with the given exports and 1 page of memory.
func buildWASMModule(exports []wasmExport) []byte {
	var buf []byte

	// Magic number and version
	buf = append(buf, 0x00, 0x61, 0x73, 0x6d) // \0asm
	buf = append(buf, 0x01, 0x00, 0x00, 0x00) // version 1

	// === Type section (section id=1) ===
	var typeSection []byte
	typeSection = append(typeSection, byte(len(exports))) // num types
	for _, e := range exports {
		typeSection = append(typeSection, 0x60) // func type
		typeSection = append(typeSection, byte(e.params))
		for i := 0; i < e.params; i++ {
			typeSection = append(typeSection, 0x7f) // i32
		}
		typeSection = append(typeSection, byte(e.results))
		for i := 0; i < e.results; i++ {
			typeSection = append(typeSection, 0x7f) // i32
		}
	}
	buf = append(buf, 0x01)                          // section id
	buf = append(buf, encodeULEB128(len(typeSection))...) // section size
	buf = append(buf, typeSection...)

	// === Function section (section id=3) ===
	var funcSection []byte
	funcSection = append(funcSection, byte(len(exports))) // num funcs
	for i := range exports {
		funcSection = append(funcSection, byte(i)) // type index
	}
	buf = append(buf, 0x03)
	buf = append(buf, encodeULEB128(len(funcSection))...)
	buf = append(buf, funcSection...)

	// === Memory section (section id=5) ===
	memSection := []byte{0x01, 0x00, 0x01} // 1 memory, min 1 page, no max
	buf = append(buf, 0x05)
	buf = append(buf, encodeULEB128(len(memSection))...)
	buf = append(buf, memSection...)

	// === Export section (section id=7) ===
	var exportSection []byte
	numExports := len(exports) + 1 // functions + memory
	exportSection = append(exportSection, byte(numExports))

	// Export memory
	exportSection = append(exportSection, byte(len("memory")))
	exportSection = append(exportSection, "memory"...)
	exportSection = append(exportSection, 0x02) // memory export
	exportSection = append(exportSection, 0x00) // memory index 0

	// Export functions
	for i, e := range exports {
		exportSection = append(exportSection, byte(len(e.name)))
		exportSection = append(exportSection, e.name...)
		exportSection = append(exportSection, 0x00) // func export
		exportSection = append(exportSection, byte(i))
	}
	buf = append(buf, 0x07)
	buf = append(buf, encodeULEB128(len(exportSection))...)
	buf = append(buf, exportSection...)

	// === Code section (section id=10) ===
	var codeSection []byte
	codeSection = append(codeSection, byte(len(exports))) // num funcs
	for _, e := range exports {
		body := append(e.body, 0x0b) // end
		funcBody := append([]byte{0x00}, body...) // 0 locals + body
		codeSection = append(codeSection, encodeULEB128(len(funcBody))...)
		codeSection = append(codeSection, funcBody...)
	}
	buf = append(buf, 0x0a)
	buf = append(buf, encodeULEB128(len(codeSection))...)
	buf = append(buf, codeSection...)

	return buf
}

// encodeI32Const encodes an i32.const instruction with the given value.
func encodeI32Const(val int) []byte {
	return append([]byte{0x41}, encodeSLEB128(val)...)
}

// encodeULEB128 encodes an unsigned integer in LEB128 format.
func encodeULEB128(val int) []byte {
	if val < 0 {
		val = 0
	}
	var result []byte
	for {
		b := byte(val & 0x7f)
		val >>= 7
		if val != 0 {
			b |= 0x80
		}
		result = append(result, b)
		if val == 0 {
			break
		}
	}
	return result
}

// encodeSLEB128 encodes a signed integer in LEB128 format.
func encodeSLEB128(val int) []byte {
	var result []byte
	for {
		b := byte(val & 0x7f)
		val >>= 7
		if (val == 0 && b&0x40 == 0) || (val == -1 && b&0x40 != 0) {
			result = append(result, b)
			break
		}
		result = append(result, b|0x80)
	}
	return result
}
