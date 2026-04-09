package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWasmAction_Registration(t *testing.T) {
	if _, ok := loaderFns[TypeWasm]; !ok {
		t.Fatal("wasm action not registered in loaderFns")
	}
}

func TestWasmAction_LoadWasmAction(t *testing.T) {
	data := `{
		"type": "wasm",
		"config": {
			"module": "/path/to/action.wasm",
			"timeout_ms": 150,
			"memory_limit_mb": 24
		}
	}`

	action, err := LoadWasmAction([]byte(data))
	if err != nil {
		t.Fatalf("LoadWasmAction() error = %v", err)
	}

	if action.GetType() != TypeWasm {
		t.Errorf("GetType() = %q, want %q", action.GetType(), TypeWasm)
	}

	wasm := action.(*WasmActionConfig)
	if wasm.WasmConfig == nil {
		t.Fatal("WasmConfig should not be nil")
	}
	if wasm.WasmConfig.Module != "/path/to/action.wasm" {
		t.Errorf("Module = %q, want %q", wasm.WasmConfig.Module, "/path/to/action.wasm")
	}
	if wasm.WasmConfig.TimeoutMS != 150 {
		t.Errorf("TimeoutMS = %d, want 150", wasm.WasmConfig.TimeoutMS)
	}
	if wasm.WasmConfig.MemoryLimitMB != 24 {
		t.Errorf("MemoryLimitMB = %d, want 24", wasm.WasmConfig.MemoryLimitMB)
	}
}

func TestWasmAction_LoadActionConfig(t *testing.T) {
	data := `{"type": "wasm", "config": {"module": "test.wasm"}}`

	action, err := LoadActionConfig(json.RawMessage(data))
	if err != nil {
		t.Fatalf("LoadActionConfig() error = %v", err)
	}

	if action.GetType() != TypeWasm {
		t.Errorf("GetType() = %q, want %q", action.GetType(), TypeWasm)
	}
}

func TestWasmAction_InvalidJSON(t *testing.T) {
	_, err := LoadWasmAction([]byte("invalid json"))
	if err == nil {
		t.Error("LoadWasmAction() should fail with invalid JSON")
	}
}

func TestWasmAction_Defaults(t *testing.T) {
	data := `{"type": "wasm", "config": {"module": "test.wasm"}}`

	action, err := LoadWasmAction([]byte(data))
	if err != nil {
		t.Fatalf("LoadWasmAction() error = %v", err)
	}

	wasm := action.(*WasmActionConfig)
	if wasm.WasmConfig.MemoryLimit() != 16 {
		t.Errorf("MemoryLimit() = %d, want 16", wasm.WasmConfig.MemoryLimit())
	}
	if wasm.WasmConfig.Timeout().Milliseconds() != 50 {
		t.Errorf("Timeout() = %v, want 50ms", wasm.WasmConfig.Timeout())
	}
}

func TestWasmAction_HandlerWithoutInit(t *testing.T) {
	data := `{"type": "wasm", "config": {"module": "test.wasm"}}`

	action, err := LoadWasmAction([]byte(data))
	if err != nil {
		t.Fatalf("LoadWasmAction() error = %v", err)
	}

	// Without Init, middleware is nil, so Handler should return a default 200 handler
	handler := action.Handler()
	if handler == nil {
		t.Fatal("Handler() should not return nil even without Init")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Handler status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestWasmAction_IsProxy(t *testing.T) {
	data := `{"type": "wasm", "config": {"module": "test.wasm"}}`

	action, err := LoadWasmAction([]byte(data))
	if err != nil {
		t.Fatalf("LoadWasmAction() error = %v", err)
	}

	// WASM action is not a proxy type
	if action.IsProxy() {
		t.Error("IsProxy() should be false for WASM action")
	}
}

func TestWasmAction_WithPluginConfig(t *testing.T) {
	data := `{
		"type": "wasm",
		"config": {
			"module": "action.wasm",
			"config": {"handler": "custom"},
			"sha256": "xyz789"
		}
	}`

	action, err := LoadWasmAction([]byte(data))
	if err != nil {
		t.Fatalf("LoadWasmAction() error = %v", err)
	}

	wasm := action.(*WasmActionConfig)
	if wasm.WasmConfig.SHA256 != "xyz789" {
		t.Errorf("SHA256 = %q, want %q", wasm.WasmConfig.SHA256, "xyz789")
	}
	if wasm.WasmConfig.Config == nil {
		t.Error("Config should not be nil")
	}
}
