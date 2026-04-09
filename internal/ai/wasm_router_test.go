package ai

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/extension/wasm"
)

func TestWASMRouterConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     WASMRouterConfig
		wantErr bool
	}{
		{
			name:    "empty module path",
			cfg:     WASMRouterConfig{},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: WASMRouterConfig{
				ModulePath: "/path/to/router.wasm",
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

func TestNewWASMRouter_Errors(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	t.Run("nil runtime", func(t *testing.T) {
		_, err := NewWASMRouter(WASMRouterConfig{ModulePath: "/tmp/test.wasm"}, nil)
		if err == nil {
			t.Error("expected error for nil runtime")
		}
	})

	t.Run("empty module path", func(t *testing.T) {
		_, err := NewWASMRouter(WASMRouterConfig{}, rt)
		if err == nil {
			t.Error("expected error for empty module path")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := NewWASMRouter(WASMRouterConfig{ModulePath: "/nonexistent/router.wasm"}, rt)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("default timeout applied", func(t *testing.T) {
		tmpDir := t.TempDir()
		wasmPath := filepath.Join(tmpDir, "test.wasm")
		if err := os.WriteFile(wasmPath, []byte("fake wasm content"), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		wr, err := NewWASMRouter(WASMRouterConfig{ModulePath: wasmPath}, rt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wr.config.Timeout != 100*time.Millisecond {
			t.Errorf("default timeout = %v, want %v", wr.config.Timeout, 100*time.Millisecond)
		}
	})
}

func TestWASMRouter_Route(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	// Build a WASM module that exports select_provider.
	// The module writes a fixed provider name "openai" to memory at offset 2048
	// and returns (2048, 6).
	providerName := "openai"
	wasmBytes := buildRouterModule(providerName)

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "router.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
		t.Fatalf("failed to write wasm: %v", err)
	}

	wr, err := NewWASMRouter(WASMRouterConfig{ModulePath: wasmPath}, rt)
	if err != nil {
		t.Fatalf("NewWASMRouter: %v", err)
	}

	result, err := wr.Route(ctx, "gpt-4", []string{"openai", "azure", "anthropic"})
	if err != nil {
		t.Fatalf("Route: %v", err)
	}

	if result != providerName {
		t.Errorf("Route() = %q, want %q", result, providerName)
	}
}

func TestWASMRouter_Route_SHA256Check(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "router.wasm")
	if err := os.WriteFile(wasmPath, []byte("fake wasm"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err = NewWASMRouter(WASMRouterConfig{
		ModulePath: wasmPath,
		SHA256:     "badhash",
	}, rt)
	if err == nil {
		t.Error("expected error for bad SHA256")
	}
}

// buildRouterModule creates a WASM module that exports select_provider.
// The function stores the provider name at a fixed memory offset and returns (offset, len).
func buildRouterModule(providerName string) []byte {
	nameBytes := []byte(providerName)
	offset := 2048

	// Build the function body that:
	// 1. Stores each byte of the provider name at memory offset 2048+
	// 2. Returns (2048, len)
	var body []byte
	for i, b := range nameBytes {
		// i32.const <offset+i>
		body = append(body, 0x41)
		body = append(body, encodeSLEB128(offset+i)...)
		// i32.const <byte>
		body = append(body, 0x41)
		body = append(body, encodeSLEB128(int(b))...)
		// i32.store8 align=0 offset=0
		body = append(body, 0x3a, 0x00, 0x00)
	}
	// Return (offset, len)
	body = append(body, 0x41)
	body = append(body, encodeSLEB128(offset)...)
	body = append(body, 0x41)
	body = append(body, encodeSLEB128(len(nameBytes))...)

	return buildWASMModule([]wasmExport{
		{name: "sb_malloc", params: 1, results: 1, body: []byte{0x41, 0x80, 0x08}}, // i32.const 1024
		{name: "select_provider", params: 2, results: 2, body: body},
	})
}
