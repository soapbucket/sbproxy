package ai

import (
	"context"
	"fmt"
	"time"
)

// WASMCompressorConfig configures a WASM-based compression plugin.
type WASMCompressorConfig struct {
	ModulePath string        `json:"module_path"`
	SHA256     string        `json:"sha256,omitempty"`
	Timeout    time.Duration `json:"timeout,omitempty"`
}

// Validate checks the configuration for required fields.
func (c *WASMCompressorConfig) Validate() error {
	if c.ModulePath == "" {
		return fmt.Errorf("wasm compressor: module_path is required")
	}
	return nil
}

// WASMCompressor applies WASM-based compression to data.
// In the open-source build, WASM is not available.
type WASMCompressor struct{}

// NewWASMCompressor returns an error because WASM is not available in this build.
func NewWASMCompressor(cfg WASMCompressorConfig, _ interface{}) (*WASMCompressor, error) {
	return nil, fmt.Errorf("wasm compressor: not available in this build")
}

// Compress is unreachable because NewWASMCompressor always returns an error.
func (wc *WASMCompressor) Compress(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("wasm compressor: not available in this build")
}
