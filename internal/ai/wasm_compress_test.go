package ai

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/extension/wasm"
)

func TestWASMCompressorConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     WASMCompressorConfig
		wantErr bool
	}{
		{
			name:    "empty module path",
			cfg:     WASMCompressorConfig{},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: WASMCompressorConfig{
				ModulePath: "/path/to/compress.wasm",
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

func TestNewWASMCompressor_Errors(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	t.Run("nil runtime", func(t *testing.T) {
		_, err := NewWASMCompressor(WASMCompressorConfig{ModulePath: "/tmp/test.wasm"}, nil)
		if err == nil {
			t.Error("expected error for nil runtime")
		}
	})

	t.Run("empty module path", func(t *testing.T) {
		_, err := NewWASMCompressor(WASMCompressorConfig{}, rt)
		if err == nil {
			t.Error("expected error for empty module path")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := NewWASMCompressor(WASMCompressorConfig{ModulePath: "/nonexistent/compress.wasm"}, rt)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("sha256 mismatch", func(t *testing.T) {
		tmpDir := t.TempDir()
		wasmPath := filepath.Join(tmpDir, "test.wasm")
		if err := os.WriteFile(wasmPath, []byte("not real wasm"), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		_, err := NewWASMCompressor(WASMCompressorConfig{
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

		wc, err := NewWASMCompressor(WASMCompressorConfig{ModulePath: wasmPath}, rt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wc.config.Timeout != 100*time.Millisecond {
			t.Errorf("default timeout = %v, want %v", wc.config.Timeout, 100*time.Millisecond)
		}
	})
}

func TestWASMCompressor_Compress_Identity(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	// Build a WASM module with an identity compress function (returns input as-is).
	wasmBytes := buildWASMModule([]wasmExport{
		{name: "sb_malloc", params: 1, results: 1, body: []byte{0x41, 0x80, 0x08}}, // i32.const 1024
		{name: "compress", params: 2, results: 2, body: []byte{
			0x20, 0x00, // local.get 0 (ptr)
			0x20, 0x01, // local.get 1 (len)
		}},
	})

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "compress.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
		t.Fatalf("failed to write wasm: %v", err)
	}

	wc, err := NewWASMCompressor(WASMCompressorConfig{ModulePath: wasmPath}, rt)
	if err != nil {
		t.Fatalf("NewWASMCompressor: %v", err)
	}

	input := []byte(`{"messages":[{"role":"user","content":"Hello, how are you?"}]}`)
	output, err := wc.Compress(ctx, input)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}

	if string(output) != string(input) {
		t.Errorf("output = %q, want %q", string(output), string(input))
	}
}

func TestWASMCompressor_Compress_EmptyInput(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	wasmBytes := buildWASMModule([]wasmExport{
		{name: "sb_malloc", params: 1, results: 1, body: []byte{0x41, 0x80, 0x08}},
		{name: "compress", params: 2, results: 2, body: []byte{
			0x20, 0x00,
			0x20, 0x01,
		}},
	})

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "compress_empty.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
		t.Fatalf("failed to write wasm: %v", err)
	}

	wc, err := NewWASMCompressor(WASMCompressorConfig{ModulePath: wasmPath}, rt)
	if err != nil {
		t.Fatalf("NewWASMCompressor: %v", err)
	}

	output, err := wc.Compress(ctx, nil)
	if err != nil {
		t.Fatalf("Compress with nil input: %v", err)
	}
	if output != nil {
		t.Errorf("expected nil output for nil input, got %v", output)
	}
}

func TestWASMCompressor_Compress_LargeInput(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	wasmBytes := buildWASMModule([]wasmExport{
		{name: "sb_malloc", params: 1, results: 1, body: []byte{0x41, 0x80, 0x08}},
		{name: "compress", params: 2, results: 2, body: []byte{
			0x20, 0x00,
			0x20, 0x01,
		}},
	})

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "compress_large.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
		t.Fatalf("failed to write wasm: %v", err)
	}

	wc, err := NewWASMCompressor(WASMCompressorConfig{ModulePath: wasmPath}, rt)
	if err != nil {
		t.Fatalf("NewWASMCompressor: %v", err)
	}

	// Create a moderately large input (within 1 WASM page = 64KB).
	input := make([]byte, 4096)
	for i := range input {
		input[i] = byte('A' + (i % 26))
	}

	output, err := wc.Compress(ctx, input)
	if err != nil {
		t.Fatalf("Compress large input: %v", err)
	}

	if len(output) != len(input) {
		t.Errorf("output length = %d, want %d", len(output), len(input))
	}
}
