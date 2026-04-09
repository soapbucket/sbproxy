package wasm

import (
	"context"
	"fmt"
	"testing"
)

func TestCompile_ClosedRuntime(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	rt.Close(ctx)

	_, err = rt.Compile(ctx, "test", []byte{0x00, 0x61, 0x73, 0x6d})
	if err == nil {
		t.Error("expected error from Compile on closed runtime")
	}
}

func TestCompile_EmptyName(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	_, err = rt.Compile(ctx, "", []byte{0x00})
	if err == nil {
		t.Error("expected error for empty module name")
	}
}

func TestCompile_EmptyBytes(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	_, err = rt.Compile(ctx, "test", nil)
	if err == nil {
		t.Error("expected error for nil wasm bytes")
	}

	_, err = rt.Compile(ctx, "test", []byte{})
	if err == nil {
		t.Error("expected error for empty wasm bytes")
	}
}

func TestCompile_InvalidWasm(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	_, err = rt.Compile(ctx, "test", []byte("not a wasm module"))
	if err == nil {
		t.Error("expected error for invalid wasm bytes")
	}
}

func TestValidateExports_NoLifecycleHooks(t *testing.T) {
	cm := &CompiledModule{
		name: "test",
		exports: ModuleExports{
			HasOnRequest:  false,
			HasOnResponse: false,
			HasMalloc:     true,
		},
	}

	err := cm.ValidateExports()
	if err == nil {
		t.Error("expected error when no lifecycle hooks are exported")
	}
}

func TestValidateExports_NoMalloc(t *testing.T) {
	cm := &CompiledModule{
		name: "test",
		exports: ModuleExports{
			HasOnRequest:  true,
			HasOnResponse: false,
			HasMalloc:     false,
		},
	}

	err := cm.ValidateExports()
	if err == nil {
		t.Error("expected error when sb_malloc is not exported")
	}
}

func TestValidateExports_Valid(t *testing.T) {
	tests := []struct {
		name    string
		exports ModuleExports
	}{
		{
			name: "on_request only",
			exports: ModuleExports{
				HasOnRequest: true,
				HasMalloc:    true,
			},
		},
		{
			name: "on_response only",
			exports: ModuleExports{
				HasOnResponse: true,
				HasMalloc:     true,
			},
		},
		{
			name: "both hooks",
			exports: ModuleExports{
				HasOnRequest:  true,
				HasOnResponse: true,
				HasMalloc:     true,
			},
		},
		{
			name: "all exports",
			exports: ModuleExports{
				HasOnConfig:   true,
				HasOnRequest:  true,
				HasOnResponse: true,
				HasMalloc:     true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := &CompiledModule{
				name:    "test",
				exports: tt.exports,
			}
			if err := cm.ValidateExports(); err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestCompiledModule_Accessors(t *testing.T) {
	exports := ModuleExports{
		HasOnRequest: true,
		HasMalloc:    true,
	}
	cm := &CompiledModule{
		name:    "my-module",
		exports: exports,
	}

	if cm.Name() != "my-module" {
		t.Errorf("expected name %q, got %q", "my-module", cm.Name())
	}

	got := cm.Exports()
	if got != exports {
		t.Errorf("exports mismatch: got %+v, want %+v", got, exports)
	}
}

func TestCompiledModule_CloseNil(t *testing.T) {
	cm := &CompiledModule{
		name:     "test",
		compiled: nil,
	}
	if err := cm.Close(context.Background()); err != nil {
		t.Errorf("unexpected error closing nil compiled module: %v", err)
	}
}

func TestValidateExports_ErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		exports  ModuleExports
		wantMsg  string
	}{
		{
			name: "no hooks mentions module name",
			exports: ModuleExports{HasMalloc: true},
			wantMsg: "must export at least one",
		},
		{
			name: "no malloc mentions sb_malloc",
			exports: ModuleExports{HasOnRequest: true},
			wantMsg: "sb_malloc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := &CompiledModule{name: "test-mod", exports: tt.exports}
			err := cm.ValidateExports()
			if err == nil {
				t.Fatal("expected error")
			}
			msg := fmt.Sprintf("%v", err)
			if len(msg) == 0 {
				t.Error("error message should not be empty")
			}
		})
	}
}
