// Package featureflags manages runtime feature flags for gradual rollouts and A/B testing.
package featureflags

import (
	"context"
	"sync"
)

var (
	globalMu      sync.RWMutex
	globalManager Manager = NoopManager{}
)

// SetGlobalManager sets the global feature flag manager.
func SetGlobalManager(m Manager) {
	globalMu.Lock()
	globalManager = m
	globalMu.Unlock()
}

// GetGlobalManager returns the current global feature flag manager.
func GetGlobalManager() Manager {
	globalMu.RLock()
	m := globalManager
	globalMu.RUnlock()
	return m
}

// GlobalGetFlags is a convenience function for use as a getter callback.
func GlobalGetFlags(ctx context.Context, workspaceID string) map[string]any {
	return GetGlobalManager().GetFlags(ctx, workspaceID)
}
