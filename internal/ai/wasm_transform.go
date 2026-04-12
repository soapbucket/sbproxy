// wasm_transform.go defines WASM-based request/response transform configuration and stub.
package ai

import (
	"context"
	"fmt"
	"time"
)

// WASMTransformPhase defines when the transform runs.
type WASMTransformPhase string

const (
	// WASMTransformPhasePre runs before forwarding to the upstream provider.
	WASMTransformPhasePre WASMTransformPhase = "pre"
	// WASMTransformPhasePost runs after receiving the response from the upstream provider.
	WASMTransformPhasePost WASMTransformPhase = "post"
)

// WASMTransformConfig configures a WASM-based request/response transformer.
type WASMTransformConfig struct {
	ModulePath string             `json:"module_path"`
	Phase      WASMTransformPhase `json:"phase"`
	SHA256     string             `json:"sha256,omitempty"`
	Timeout    time.Duration      `json:"timeout,omitempty"`
}

// Validate checks the configuration for required fields.
func (c *WASMTransformConfig) Validate() error {
	if c.ModulePath == "" {
		return fmt.Errorf("wasm transform: module_path is required")
	}
	if c.Phase != WASMTransformPhasePre && c.Phase != WASMTransformPhasePost {
		return fmt.Errorf("wasm transform: phase must be %q or %q, got %q", WASMTransformPhasePre, WASMTransformPhasePost, c.Phase)
	}
	return nil
}

// WASMTransform applies WASM-based request or response transformations.
// In the open-source build, WASM is not available.
type WASMTransform struct {
	config WASMTransformConfig
}

// NewWASMTransform returns an error because WASM is not available in this build.
func NewWASMTransform(cfg WASMTransformConfig, _ interface{}) (*WASMTransform, error) {
	return nil, fmt.Errorf("wasm transform: not available in this build")
}

// Transform is unreachable because NewWASMTransform always returns an error.
func (wt *WASMTransform) Transform(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("wasm transform: not available in this build")
}

// Phase returns the configured transform phase.
func (wt *WASMTransform) Phase() WASMTransformPhase {
	return wt.config.Phase
}
