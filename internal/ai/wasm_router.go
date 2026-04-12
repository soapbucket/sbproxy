// wasm_router.go defines WASM-based routing plugin configuration and stub.
package ai

import (
	"context"
	"fmt"
	"time"
)

// WASMRouterConfig configures a WASM-based routing plugin.
type WASMRouterConfig struct {
	ModulePath string        `json:"module_path"`
	SHA256     string        `json:"sha256,omitempty"`
	Timeout    time.Duration `json:"timeout,omitempty"`
}

// Validate checks the configuration for required fields.
func (c *WASMRouterConfig) Validate() error {
	if c.ModulePath == "" {
		return fmt.Errorf("wasm router: module_path is required")
	}
	return nil
}

// WASMRouter selects an AI provider using a WASM module.
// In the open-source build, WASM is not available.
type WASMRouter struct{}

// NewWASMRouter returns an error because WASM is not available in this build.
func NewWASMRouter(cfg WASMRouterConfig, _ interface{}) (*WASMRouter, error) {
	return nil, fmt.Errorf("wasm router: not available in this build")
}

// Route is unreachable because NewWASMRouter always returns an error.
func (wr *WASMRouter) Route(_ context.Context, _ string, _ []string) (string, error) {
	return "", fmt.Errorf("wasm router: not available in this build")
}
