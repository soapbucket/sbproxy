package ai

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/extension/wasm"
)

func TestWASMTransformConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     WASMTransformConfig
		wantErr bool
	}{
		{
			name:    "empty module path",
			cfg:     WASMTransformConfig{Phase: WASMTransformPhasePre},
			wantErr: true,
		},
		{
			name:    "invalid phase",
			cfg:     WASMTransformConfig{ModulePath: "/path/to/module.wasm", Phase: "invalid"},
			wantErr: true,
		},
		{
			name: "valid pre config",
			cfg: WASMTransformConfig{
				ModulePath: "/path/to/module.wasm",
				Phase:      WASMTransformPhasePre,
			},
			wantErr: false,
		},
		{
			name: "valid post config",
			cfg: WASMTransformConfig{
				ModulePath: "/path/to/module.wasm",
				Phase:      WASMTransformPhasePost,
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

func TestNewWASMTransform_Errors(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	t.Run("nil runtime", func(t *testing.T) {
		_, err := NewWASMTransform(WASMTransformConfig{ModulePath: "/tmp/test.wasm", Phase: WASMTransformPhasePre}, nil)
		if err == nil {
			t.Error("expected error for nil runtime")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := NewWASMTransform(WASMTransformConfig{ModulePath: "/nonexistent/module.wasm", Phase: WASMTransformPhasePre}, rt)
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

		_, err := NewWASMTransform(WASMTransformConfig{
			ModulePath: wasmPath,
			Phase:      WASMTransformPhasePre,
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

		wt, err := NewWASMTransform(WASMTransformConfig{
			ModulePath: wasmPath,
			Phase:      WASMTransformPhasePre,
		}, rt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wt.config.Timeout != 100*time.Millisecond {
			t.Errorf("default timeout = %v, want %v", wt.config.Timeout, 100*time.Millisecond)
		}
	})
}

func TestWASMTransform_Phase(t *testing.T) {
	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "test.wasm")
	if err := os.WriteFile(wasmPath, []byte("fake"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	wt, err := NewWASMTransform(WASMTransformConfig{
		ModulePath: wasmPath,
		Phase:      WASMTransformPhasePost,
	}, rt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wt.Phase() != WASMTransformPhasePost {
		t.Errorf("Phase() = %q, want %q", wt.Phase(), WASMTransformPhasePost)
	}
}

func TestWASMTransform_Transform_PrePhase(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	// Build a WASM module that exports transform_request, returning the input as-is.
	// The function just returns the input ptr/len unchanged (identity transform).
	wasmBytes := buildWASMModule([]wasmExport{
		{name: "sb_malloc", params: 1, results: 1, body: []byte{0x41, 0x80, 0x08}}, // i32.const 1024
		{name: "transform_request", params: 2, results: 2, body: []byte{
			0x20, 0x00, // local.get 0 (ptr)
			0x20, 0x01, // local.get 1 (len)
		}},
	})

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "transform.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
		t.Fatalf("failed to write wasm: %v", err)
	}

	wt, err := NewWASMTransform(WASMTransformConfig{
		ModulePath: wasmPath,
		Phase:      WASMTransformPhasePre,
	}, rt)
	if err != nil {
		t.Fatalf("NewWASMTransform: %v", err)
	}

	input := []byte(`{"model":"gpt-4","messages":[]}`)
	output, err := wt.Transform(ctx, input)
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}

	// The identity transform should return the same data.
	if string(output) != string(input) {
		t.Errorf("output = %q, want %q", string(output), string(input))
	}
}

func TestWASMTransform_Transform_PostPhase(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	// Build a WASM module with transform_response (identity).
	wasmBytes := buildWASMModule([]wasmExport{
		{name: "sb_malloc", params: 1, results: 1, body: []byte{0x41, 0x80, 0x08}},
		{name: "transform_response", params: 2, results: 2, body: []byte{
			0x20, 0x00,
			0x20, 0x01,
		}},
	})

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "transform_post.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
		t.Fatalf("failed to write wasm: %v", err)
	}

	wt, err := NewWASMTransform(WASMTransformConfig{
		ModulePath: wasmPath,
		Phase:      WASMTransformPhasePost,
	}, rt)
	if err != nil {
		t.Fatalf("NewWASMTransform: %v", err)
	}

	input := []byte(`{"response":"ok"}`)
	output, err := wt.Transform(ctx, input)
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}

	if string(output) != string(input) {
		t.Errorf("output = %q, want %q", string(output), string(input))
	}
}

func TestWASMTransform_Transform_EmptyInput(t *testing.T) {
	ctx := context.Background()
	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	wasmBytes := buildWASMModule([]wasmExport{
		{name: "sb_malloc", params: 1, results: 1, body: []byte{0x41, 0x80, 0x08}},
		{name: "transform_request", params: 2, results: 2, body: []byte{
			0x20, 0x00,
			0x20, 0x01,
		}},
	})

	tmpDir := t.TempDir()
	wasmPath := filepath.Join(tmpDir, "transform_empty.wasm")
	if err := os.WriteFile(wasmPath, wasmBytes, 0644); err != nil {
		t.Fatalf("failed to write wasm: %v", err)
	}

	wt, err := NewWASMTransform(WASMTransformConfig{
		ModulePath: wasmPath,
		Phase:      WASMTransformPhasePre,
	}, rt)
	if err != nil {
		t.Fatalf("NewWASMTransform: %v", err)
	}

	// Empty input should not cause an error.
	output, err := wt.Transform(ctx, nil)
	if err != nil {
		t.Fatalf("Transform with nil input: %v", err)
	}
	// With nil/empty input, ptr=0 and len=0, the identity transform returns (0, 0).
	if output != nil {
		t.Errorf("expected nil output for nil input, got %v", output)
	}
}
