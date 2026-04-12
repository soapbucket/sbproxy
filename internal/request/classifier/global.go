// global.go manages the package-level ManagedClient and TenantSync singletons.
package classifier

import "sync"

var (
	globalClient *ManagedClient
	globalMu     sync.RWMutex

	globalSync *TenantSync
	syncMu     sync.RWMutex
)

// SetGlobal sets the package-level ManagedClient singleton.
// Called by Service.initClassifier after successful initialization.
func SetGlobal(mc *ManagedClient) {
	globalMu.Lock()
	globalClient = mc
	globalMu.Unlock()
}

// Global returns the package-level ManagedClient, or nil if the classifier
// sidecar is not configured. Callers must check for nil before use.
func Global() *ManagedClient {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalClient
}

// SetGlobalSync sets the package-level TenantSync singleton.
// Called by Service.initClassifier after creating the TenantSync.
func SetGlobalSync(ts *TenantSync) {
	syncMu.Lock()
	globalSync = ts
	syncMu.Unlock()
}

// GlobalSync returns the package-level TenantSync, or nil if the classifier
// sidecar is not configured. Callers must check for nil before use.
func GlobalSync() *TenantSync {
	syncMu.RLock()
	defer syncMu.RUnlock()
	return globalSync
}
