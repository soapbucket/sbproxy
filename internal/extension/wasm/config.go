package wasm

import (
	"encoding/json"
	"time"
)

// WasmPluginConfig is the JSON config for WASM plugins used across policy/transform/action.
type WasmPluginConfig struct {
	Module        string          `json:"module"`                    // File path or URL to .wasm
	Config        json.RawMessage `json:"config,omitempty"`          // Plugin-specific config
	TimeoutMS     int             `json:"timeout_ms,omitempty"`      // Max execution time (default: 50)
	MemoryLimitMB int             `json:"memory_limit_mb,omitempty"` // Max memory (default: 16)
	SHA256        string          `json:"sha256,omitempty"`          // Integrity check for URL modules
}

// Timeout returns the configured timeout or default.
func (c *WasmPluginConfig) Timeout() time.Duration {
	if c.TimeoutMS <= 0 {
		return 50 * time.Millisecond
	}
	return time.Duration(c.TimeoutMS) * time.Millisecond
}

// MemoryLimit returns memory limit in MB.
func (c *WasmPluginConfig) MemoryLimit() int {
	if c.MemoryLimitMB <= 0 {
		return 16
	}
	return c.MemoryLimitMB
}
