package config

import "sync"

var (
	serverVaultsMu   sync.RWMutex
	serverVaultsDefs map[string]VaultDefinition
)

// SetServerVaults stores server-level vault definitions (called once at startup).
func SetServerVaults(defs map[string]VaultDefinition) {
	serverVaultsMu.Lock()
	defer serverVaultsMu.Unlock()
	serverVaultsDefs = defs
}

// GetServerVaults returns the server-level vault definitions.
func GetServerVaults() map[string]VaultDefinition {
	serverVaultsMu.RLock()
	defer serverVaultsMu.RUnlock()
	return serverVaultsDefs
}

// MergeVaults returns a merged map where origin-level definitions override server-level.
func MergeVaults(serverDefs, originDefs map[string]VaultDefinition) map[string]VaultDefinition {
	if len(serverDefs) == 0 && len(originDefs) == 0 {
		return nil
	}
	if len(serverDefs) == 0 {
		return originDefs
	}
	if len(originDefs) == 0 {
		return serverDefs
	}
	merged := make(map[string]VaultDefinition, len(serverDefs)+len(originDefs))
	for k, v := range serverDefs {
		merged[k] = v
	}
	for k, v := range originDefs {
		merged[k] = v
	}
	return merged
}
