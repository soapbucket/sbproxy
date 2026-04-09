package config

import (
	"encoding/json"
	"testing"
)

func TestWasmPolicy_Registration(t *testing.T) {
	if _, ok := policyLoaderFns[PolicyTypeWasm]; !ok {
		t.Fatal("wasm policy not registered in policyLoaderFns")
	}
}

func TestWasmPolicy_NewWasmPolicy(t *testing.T) {
	data := `{
		"type": "wasm",
		"config": {
			"module": "/path/to/policy.wasm",
			"timeout_ms": 100,
			"memory_limit_mb": 32
		}
	}`

	policy, err := NewWasmPolicy([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmPolicy() error = %v", err)
	}

	if policy.GetType() != PolicyTypeWasm {
		t.Errorf("GetType() = %q, want %q", policy.GetType(), PolicyTypeWasm)
	}

	wasm := policy.(*WasmPolicyConfig)
	if wasm.WasmConfig == nil {
		t.Fatal("WasmConfig should not be nil")
	}
	if wasm.WasmConfig.Module != "/path/to/policy.wasm" {
		t.Errorf("Module = %q, want %q", wasm.WasmConfig.Module, "/path/to/policy.wasm")
	}
	if wasm.WasmConfig.TimeoutMS != 100 {
		t.Errorf("TimeoutMS = %d, want 100", wasm.WasmConfig.TimeoutMS)
	}
	if wasm.WasmConfig.MemoryLimitMB != 32 {
		t.Errorf("MemoryLimitMB = %d, want 32", wasm.WasmConfig.MemoryLimitMB)
	}
}

func TestWasmPolicy_LoadPolicyConfig(t *testing.T) {
	data := `{"type": "wasm", "config": {"module": "test.wasm"}}`

	policy, err := LoadPolicyConfig([]byte(data))
	if err != nil {
		t.Fatalf("LoadPolicyConfig() error = %v", err)
	}

	if policy.GetType() != PolicyTypeWasm {
		t.Errorf("GetType() = %q, want %q", policy.GetType(), PolicyTypeWasm)
	}
}

func TestWasmPolicy_Disabled(t *testing.T) {
	data := `{"type": "wasm", "disabled": true, "config": {"module": "test.wasm"}}`

	policy, err := NewWasmPolicy([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmPolicy() error = %v", err)
	}

	wasm := policy.(*WasmPolicyConfig)
	if !wasm.Disabled {
		t.Error("Disabled should be true")
	}
}

func TestWasmPolicy_InvalidJSON(t *testing.T) {
	_, err := NewWasmPolicy([]byte("invalid json"))
	if err == nil {
		t.Error("NewWasmPolicy() should fail with invalid JSON")
	}
}

func TestWasmPolicy_Defaults(t *testing.T) {
	data := `{"type": "wasm", "config": {"module": "test.wasm"}}`

	policy, err := NewWasmPolicy([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmPolicy() error = %v", err)
	}

	wasm := policy.(*WasmPolicyConfig)
	if wasm.WasmConfig.MemoryLimit() != 16 {
		t.Errorf("MemoryLimit() = %d, want 16", wasm.WasmConfig.MemoryLimit())
	}
	if wasm.WasmConfig.Timeout().Milliseconds() != 50 {
		t.Errorf("Timeout() = %v, want 50ms", wasm.WasmConfig.Timeout())
	}
}

func TestWasmPolicy_WithPluginConfig(t *testing.T) {
	data := `{
		"type": "wasm",
		"config": {
			"module": "plugin.wasm",
			"config": {"allowed_paths": ["/api"]},
			"sha256": "abc123"
		}
	}`

	policy, err := NewWasmPolicy([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmPolicy() error = %v", err)
	}

	wasm := policy.(*WasmPolicyConfig)
	if wasm.WasmConfig.SHA256 != "abc123" {
		t.Errorf("SHA256 = %q, want %q", wasm.WasmConfig.SHA256, "abc123")
	}
	if wasm.WasmConfig.Config == nil {
		t.Error("Config should not be nil")
	}

	var pluginCfg map[string]json.RawMessage
	if err := json.Unmarshal(wasm.WasmConfig.Config, &pluginCfg); err != nil {
		t.Fatalf("failed to unmarshal plugin config: %v", err)
	}
	if _, ok := pluginCfg["allowed_paths"]; !ok {
		t.Error("plugin config missing allowed_paths key")
	}
}

func TestWasmPolicy_ApplyPassthroughWhenDisabled(t *testing.T) {
	data := `{"type": "wasm", "disabled": true, "config": {"module": "test.wasm"}}`
	policy, err := NewWasmPolicy([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmPolicy() error = %v", err)
	}

	wasm := policy.(*WasmPolicyConfig)
	// middleware is nil (no Init called), and Disabled is true, so Apply should return next
	handler := wasm.Apply(nil)
	if handler != nil {
		t.Error("Apply() with disabled policy and nil next should return nil")
	}
}

func TestWasmPolicy_ApplyPassthroughNoMiddleware(t *testing.T) {
	data := `{"type": "wasm", "config": {"module": "test.wasm"}}`
	policy, err := NewWasmPolicy([]byte(data))
	if err != nil {
		t.Fatalf("NewWasmPolicy() error = %v", err)
	}

	wasm := policy.(*WasmPolicyConfig)
	// middleware is nil (no Init called), so Apply should return next
	handler := wasm.Apply(nil)
	if handler != nil {
		t.Error("Apply() with nil middleware and nil next should return nil")
	}
}
