package wasm

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWasmPluginConfig_Timeout(t *testing.T) {
	tests := []struct {
		name     string
		timeout  int
		expected time.Duration
	}{
		{"default when zero", 0, 50 * time.Millisecond},
		{"default when negative", -1, 50 * time.Millisecond},
		{"custom value", 100, 100 * time.Millisecond},
		{"small value", 1, 1 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &WasmPluginConfig{TimeoutMS: tt.timeout}
			if got := cfg.Timeout(); got != tt.expected {
				t.Errorf("Timeout() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWasmPluginConfig_MemoryLimit(t *testing.T) {
	tests := []struct {
		name     string
		limit    int
		expected int
	}{
		{"default when zero", 0, 16},
		{"default when negative", -1, 16},
		{"custom value", 32, 32},
		{"small value", 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &WasmPluginConfig{MemoryLimitMB: tt.limit}
			if got := cfg.MemoryLimit(); got != tt.expected {
				t.Errorf("MemoryLimit() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWasmPluginConfig_JSON(t *testing.T) {
	input := `{
		"module": "/path/to/plugin.wasm",
		"config": {"key": "value"},
		"timeout_ms": 200,
		"memory_limit_mb": 32,
		"sha256": "abc123"
	}`

	var cfg WasmPluginConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if cfg.Module != "/path/to/plugin.wasm" {
		t.Errorf("Module = %q, want %q", cfg.Module, "/path/to/plugin.wasm")
	}
	if cfg.TimeoutMS != 200 {
		t.Errorf("TimeoutMS = %d, want 200", cfg.TimeoutMS)
	}
	if cfg.MemoryLimitMB != 32 {
		t.Errorf("MemoryLimitMB = %d, want 32", cfg.MemoryLimitMB)
	}
	if cfg.SHA256 != "abc123" {
		t.Errorf("SHA256 = %q, want %q", cfg.SHA256, "abc123")
	}
	if cfg.Config == nil {
		t.Error("Config should not be nil")
	}
	if cfg.Timeout() != 200*time.Millisecond {
		t.Errorf("Timeout() = %v, want 200ms", cfg.Timeout())
	}
	if cfg.MemoryLimit() != 32 {
		t.Errorf("MemoryLimit() = %d, want 32", cfg.MemoryLimit())
	}
}

func TestWasmPluginConfig_JSONDefaults(t *testing.T) {
	input := `{"module": "test.wasm"}`

	var cfg WasmPluginConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if cfg.Module != "test.wasm" {
		t.Errorf("Module = %q, want %q", cfg.Module, "test.wasm")
	}
	if cfg.Timeout() != 50*time.Millisecond {
		t.Errorf("Timeout() = %v, want 50ms", cfg.Timeout())
	}
	if cfg.MemoryLimit() != 16 {
		t.Errorf("MemoryLimit() = %d, want 16", cfg.MemoryLimit())
	}
	if cfg.SHA256 != "" {
		t.Errorf("SHA256 = %q, want empty", cfg.SHA256)
	}
}

func BenchmarkWasmPluginConfig_Timeout(b *testing.B) {
	b.ReportAllocs()
	cfg := &WasmPluginConfig{TimeoutMS: 100}
	for b.Loop() {
		_ = cfg.Timeout()
	}
}

func BenchmarkWasmPluginConfig_MemoryLimit(b *testing.B) {
	b.ReportAllocs()
	cfg := &WasmPluginConfig{MemoryLimitMB: 32}
	for b.Loop() {
		_ = cfg.MemoryLimit()
	}
}
