package config

import (
	"encoding/json"
	"testing"
)

func TestWasmTransform_Registration(t *testing.T) {
	if _, ok := transformLoaderFns[TransformWasm]; !ok {
		t.Fatal("wasm transform not registered in transformLoaderFns")
	}
}

func TestWasmTransform_NewWasmTransform(t *testing.T) {
	data := `{
		"type": "wasm",
		"config": {
			"module": "/path/to/transform.wasm",
			"timeout_ms": 200,
			"memory_limit_mb": 64
		}
	}`

	transform, err := NewWasmTransform([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmTransform() error = %v", err)
	}

	if transform.GetType() != TransformWasm {
		t.Errorf("GetType() = %q, want %q", transform.GetType(), TransformWasm)
	}

	wasm := transform.(*WasmTransformConfig)
	if wasm.WasmConfig == nil {
		t.Fatal("WasmConfig should not be nil")
	}
	if wasm.WasmConfig.Module != "/path/to/transform.wasm" {
		t.Errorf("Module = %q, want %q", wasm.WasmConfig.Module, "/path/to/transform.wasm")
	}
	if wasm.WasmConfig.TimeoutMS != 200 {
		t.Errorf("TimeoutMS = %d, want 200", wasm.WasmConfig.TimeoutMS)
	}
	if wasm.WasmConfig.MemoryLimitMB != 64 {
		t.Errorf("MemoryLimitMB = %d, want 64", wasm.WasmConfig.MemoryLimitMB)
	}
}

func TestWasmTransform_LoadTransformConfig(t *testing.T) {
	data := `{"type": "wasm", "config": {"module": "test.wasm"}}`

	transform, err := LoadTransformConfig(json.RawMessage(data))
	if err != nil {
		t.Fatalf("LoadTransformConfig() error = %v", err)
	}

	if transform.GetType() != TransformWasm {
		t.Errorf("GetType() = %q, want %q", transform.GetType(), TransformWasm)
	}
}

func TestWasmTransform_Disabled(t *testing.T) {
	data := `{"type": "wasm", "disabled": true, "config": {"module": "test.wasm"}}`

	transform, err := NewWasmTransform([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmTransform() error = %v", err)
	}

	wasm := transform.(*WasmTransformConfig)
	if !wasm.Disabled {
		t.Error("Disabled should be true")
	}
}

func TestWasmTransform_InvalidJSON(t *testing.T) {
	_, err := NewWasmTransform([]byte("invalid json"))
	if err == nil {
		t.Error("NewWasmTransform() should fail with invalid JSON")
	}
}

func TestWasmTransform_Defaults(t *testing.T) {
	data := `{"type": "wasm", "config": {"module": "test.wasm"}}`

	transform, err := NewWasmTransform([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmTransform() error = %v", err)
	}

	wasm := transform.(*WasmTransformConfig)
	if wasm.WasmConfig.MemoryLimit() != 16 {
		t.Errorf("MemoryLimit() = %d, want 16", wasm.WasmConfig.MemoryLimit())
	}
	if wasm.WasmConfig.Timeout().Milliseconds() != 50 {
		t.Errorf("Timeout() = %v, want 50ms", wasm.WasmConfig.Timeout())
	}
}

func TestWasmTransform_WithPluginConfig(t *testing.T) {
	data := `{
		"type": "wasm",
		"config": {
			"module": "transform.wasm",
			"config": {"strip_headers": ["x-internal"]},
			"sha256": "def456"
		}
	}`

	transform, err := NewWasmTransform([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmTransform() error = %v", err)
	}

	wasm := transform.(*WasmTransformConfig)
	if wasm.WasmConfig.SHA256 != "def456" {
		t.Errorf("SHA256 = %q, want %q", wasm.WasmConfig.SHA256, "def456")
	}
	if wasm.WasmConfig.Config == nil {
		t.Error("Config should not be nil")
	}
}
