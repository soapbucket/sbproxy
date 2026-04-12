// vault.go monitors the health of the secrets/vault subsystem.
package health

import (
	"fmt"
	"sync"
	"time"
)

// VaultChecker monitors the health of the secrets/vault subsystem.
// It tracks the number of cached secrets, the age of the oldest cached
// secret, and the last successful vault resolution timestamp.
type VaultChecker struct {
	mu sync.RWMutex

	configured          bool
	cachedSecretCount   int
	lastResolutionTime  time.Time
	oldestSecretTime    time.Time
	maxSecretAge        time.Duration // secrets older than this trigger a degraded status
}

// VaultCheckerOption is a functional option for configuring VaultChecker.
type VaultCheckerOption func(*VaultChecker)

// WithMaxSecretAge sets the threshold after which stale secrets trigger a degraded status.
// Default is 24 hours.
func WithMaxSecretAge(d time.Duration) VaultCheckerOption {
	return func(vc *VaultChecker) {
		vc.maxSecretAge = d
	}
}

// NewVaultChecker creates a new VaultChecker with the given options.
func NewVaultChecker(opts ...VaultCheckerOption) *VaultChecker {
	vc := &VaultChecker{
		maxSecretAge: 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(vc)
	}
	return vc
}

// Name returns the component name for the health system.
func (vc *VaultChecker) Name() string {
	return "vault"
}

// Check returns the current vault health status.
// Returns "ok" when vault is configured and secrets are fresh,
// "degraded" when secrets are older than the max age threshold,
// and "ok" with a note when vault is not configured (non-vault deployments).
func (vc *VaultChecker) Check() (string, error) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	if !vc.configured {
		return "ok", nil // vault is optional; not configured is not an error
	}

	if vc.lastResolutionTime.IsZero() {
		return "", fmt.Errorf("vault is configured but secrets have never been resolved")
	}

	if vc.cachedSecretCount == 0 {
		return "ok", nil
	}

	// Check if the oldest secret exceeds the max age threshold.
	if !vc.oldestSecretTime.IsZero() && vc.maxSecretAge > 0 {
		age := time.Since(vc.oldestSecretTime)
		if age > vc.maxSecretAge {
			return "degraded", nil
		}
	}

	return "ok", nil
}

// SetConfigured marks whether the vault subsystem is configured.
func (vc *VaultChecker) SetConfigured(configured bool) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.configured = configured
}

// RecordResolution records a successful secret resolution event.
// cachedCount is the total number of secrets currently cached.
// oldestTime is the timestamp of the oldest cached secret.
func (vc *VaultChecker) RecordResolution(cachedCount int, oldestTime time.Time) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.cachedSecretCount = cachedCount
	vc.lastResolutionTime = time.Now()
	vc.oldestSecretTime = oldestTime
}

// IsConfigured returns whether the vault subsystem is configured.
func (vc *VaultChecker) IsConfigured() bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.configured
}

// CachedSecretCount returns the number of cached secrets.
func (vc *VaultChecker) CachedSecretCount() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.cachedSecretCount
}

// LastResolutionTime returns the last successful vault resolution timestamp.
func (vc *VaultChecker) LastResolutionTime() time.Time {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.lastResolutionTime
}

// OldestSecretAge returns the age of the oldest cached secret.
// Returns zero duration if no secrets are cached or no oldest time is recorded.
func (vc *VaultChecker) OldestSecretAge() time.Duration {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	if vc.oldestSecretTime.IsZero() {
		return 0
	}
	return time.Since(vc.oldestSecretTime)
}

// Details returns a map of vault health details suitable for inclusion
// in the health endpoint response.
func (vc *VaultChecker) Details() map[string]any {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	details := map[string]any{
		"configured":    vc.configured,
		"cached_count":  vc.cachedSecretCount,
	}

	if !vc.lastResolutionTime.IsZero() {
		details["last_resolution"] = vc.lastResolutionTime.UTC().Format(time.RFC3339)
	}

	if !vc.oldestSecretTime.IsZero() {
		details["oldest_secret_age"] = time.Since(vc.oldestSecretTime).Round(time.Second).String()
	}

	return details
}
