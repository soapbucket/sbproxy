// Package featureflags manages runtime feature flags for gradual rollouts and A/B testing.
package featureflags

import "context"

// Manager provides per-request feature flag evaluation.
// Flags are workspace-scoped and updated in real-time (not tied to config push).
// Configured via the feature_flags section in sb.yml.
type Manager interface {
	// GetFlags returns all feature flags for a workspace as a map.
	// The returned map is used to populate the "feature" template/Lua namespace.
	GetFlags(ctx context.Context, workspaceID string) map[string]any

	// GetFlag returns a single feature flag value and whether it exists.
	GetFlag(ctx context.Context, workspaceID string, key string) (any, bool)

	// Close releases any resources held by the manager.
	Close() error
}

// NoopManager is a no-op implementation used when feature flags are disabled.
type NoopManager struct{}

// GetFlags returns the flags for the NoopManager.
func (NoopManager) GetFlags(_ context.Context, _ string) map[string]any { return nil }

// GetFlag returns the flag for the NoopManager.
func (NoopManager) GetFlag(_ context.Context, _ string, _ string) (any, bool) {
	return nil, false
}

// Close releases resources held by the NoopManager.
func (NoopManager) Close() error { return nil }
