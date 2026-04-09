// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func init() {
	loaderFns[TypeWasm] = LoadWasmAction
	policyLoaderFns[PolicyTypeWasm] = NewWasmPolicy
	transformLoaderFns[TransformWasm] = NewWasmTransform
}

// WasmPluginConfig describes a WASM module and its resource constraints.
type WasmPluginConfig struct {
	Module        string          `json:"module"`
	TimeoutMS     int             `json:"timeout_ms,omitempty"`
	MemoryLimitMB int             `json:"memory_limit_mb,omitempty"`
	SHA256        string          `json:"sha256,omitempty"`
	Config        json.RawMessage `json:"config,omitempty"`
}

// Timeout returns the configured timeout or the default of 50ms.
func (w *WasmPluginConfig) Timeout() time.Duration {
	if w.TimeoutMS > 0 {
		return time.Duration(w.TimeoutMS) * time.Millisecond
	}
	return 50 * time.Millisecond
}

// MemoryLimit returns the configured memory limit in MB or the default of 16.
func (w *WasmPluginConfig) MemoryLimit() int {
	if w.MemoryLimitMB > 0 {
		return w.MemoryLimitMB
	}
	return 16
}

// WasmActionConfig wraps a WASM plugin as an action.
// In the open-source build the WASM runtime is not included; the action
// returns HTTP 200 OK without executing any module.
type WasmActionConfig struct {
	BaseAction
	WasmConfig *WasmPluginConfig `json:"config,omitempty"`
}

var _ ActionConfig = (*WasmActionConfig)(nil)

// LoadWasmAction creates a WasmActionConfig from raw JSON.
func LoadWasmAction(data []byte) (ActionConfig, error) {
	var cfg WasmActionConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("wasm action: %w", err)
	}
	cfg.ActionType = TypeWasm
	return &cfg, nil
}

// Handler returns a pass-through handler (enterprise builds replace this with
// the actual WASM runtime).
func (w *WasmActionConfig) Handler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
}

// IsProxy returns false; WASM actions are not proxies.
func (w *WasmActionConfig) IsProxy() bool {
	return false
}

// WasmPolicyConfig wraps a WASM plugin as a policy.
type WasmPolicyConfig struct {
	BasePolicy
	WasmConfig *WasmPluginConfig `json:"config,omitempty"`
}

// NewWasmPolicy creates a WasmPolicyConfig from raw JSON.
func NewWasmPolicy(data []byte) (PolicyConfig, error) {
	var cfg WasmPolicyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("wasm policy: %w", err)
	}
	cfg.PolicyType = PolicyTypeWasm
	return &cfg, nil
}

// Init is a no-op in the open-source build.
func (w *WasmPolicyConfig) Init(cfg *Config) error {
	return nil
}

// Apply returns next unchanged when the policy is disabled or middleware has
// not been initialized. In the open-source build no WASM runtime is available
// so this always passes through.
func (w *WasmPolicyConfig) Apply(next http.Handler) http.Handler {
	if w.Disabled {
		return next
	}
	// No middleware in open-source build - pass through.
	return next
}

// GetType returns the policy type.
func (w *WasmPolicyConfig) GetType() string {
	return PolicyTypeWasm
}

// WasmTransformConfig wraps a WASM plugin as a response transform.
type WasmTransformConfig struct {
	BaseTransform
	WasmConfig *WasmPluginConfig `json:"config,omitempty"`
}

// NewWasmTransform creates a WasmTransformConfig from raw JSON.
func NewWasmTransform(data []byte) (TransformConfig, error) {
	var cfg WasmTransformConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("wasm transform: %w", err)
	}
	cfg.TransformType = TransformWasm
	return &cfg, nil
}

// Apply is a no-op in the open-source build.
func (w *WasmTransformConfig) Apply(resp *http.Response) error {
	return nil
}
