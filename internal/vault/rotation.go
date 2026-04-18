// Package vault provides secret management, vault providers, and field-level
// secret resolution for proxy configurations.
package vault

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// RotationConfig controls secret refresh behavior.
type RotationConfig struct {
	// GracePeriodSecs is how long old secret values remain valid after rotation.
	// Default: 300 seconds (5 minutes).
	GracePeriodSecs int `json:"grace_period_secs" yaml:"grace_period_secs"`

	// ReResolveIntervalSecs is how often the background goroutine polls for
	// secret changes. Default: 60 seconds.
	ReResolveIntervalSecs int `json:"re_resolve_interval_secs" yaml:"re_resolve_interval_secs"`
}

// DefaultRotationConfig returns a RotationConfig with sensible defaults.
func DefaultRotationConfig() RotationConfig {
	return RotationConfig{
		GracePeriodSecs:       300,
		ReResolveIntervalSecs: 60,
	}
}

// gracePeriod returns the configured grace period as a time.Duration.
func (rc RotationConfig) gracePeriod() time.Duration {
	secs := rc.GracePeriodSecs
	if secs <= 0 {
		secs = 300
	}
	return time.Duration(secs) * time.Second
}

// reResolveInterval returns the configured re-resolve interval as a time.Duration.
func (rc RotationConfig) reResolveInterval() time.Duration {
	secs := rc.ReResolveIntervalSecs
	if secs <= 0 {
		secs = 60
	}
	return time.Duration(secs) * time.Second
}

// RotationManager handles secret rotation with grace periods. When a secret
// is updated, the previous value remains valid for the configured grace period,
// allowing in-flight requests using the old credential to complete successfully.
type RotationManager struct {
	mu       sync.RWMutex
	current  map[string]string    // name -> current value
	previous map[string]string    // name -> previous value (during grace)
	expiry   map[string]time.Time // name -> when previous expires
	config   RotationConfig
}

// NewRotationManager creates a RotationManager with the given configuration.
// Zero-value fields in cfg are replaced with defaults.
func NewRotationManager(cfg RotationConfig) *RotationManager {
	return &RotationManager{
		current:  make(map[string]string),
		previous: make(map[string]string),
		expiry:   make(map[string]time.Time),
		config:   cfg,
	}
}

// Update sets a new value for a secret, moving the old value to the grace
// period window. If the new value is the same as the current value, no
// rotation occurs.
func (rm *RotationManager) Update(name, newValue string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	oldValue, exists := rm.current[name]

	// No rotation needed if value is unchanged.
	if exists && oldValue == newValue {
		return
	}

	// Move old value into grace period if one existed.
	if exists {
		rm.previous[name] = oldValue
		rm.expiry[name] = time.Now().Add(rm.config.gracePeriod())
	}

	rm.current[name] = newValue
}

// Validate checks if a value matches the current secret OR a grace-period
// value that has not yet expired. This allows callers using the old credential
// to continue working during the grace window.
func (rm *RotationManager) Validate(name, value string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Check current value first.
	if current, ok := rm.current[name]; ok && current == value {
		return true
	}

	// Check grace-period value.
	if prev, ok := rm.previous[name]; ok && prev == value {
		if exp, hasExp := rm.expiry[name]; hasExp && time.Now().Before(exp) {
			return true
		}
	}

	return false
}

// Get returns the current value for a secret and whether it exists.
func (rm *RotationManager) Get(name string) (string, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	val, ok := rm.current[name]
	return val, ok
}

// CleanExpired removes grace-period values whose expiry time has passed.
func (rm *RotationManager) CleanExpired() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	for name, exp := range rm.expiry {
		if now.After(exp) {
			delete(rm.previous, name)
			delete(rm.expiry, name)
		}
	}
}

// StartBackground starts a goroutine that periodically re-resolves secrets
// by calling the resolver function for each name. Changed values trigger
// rotation with grace-period support. The goroutine stops when ctx is cancelled.
func (rm *RotationManager) StartBackground(ctx context.Context, names []string, resolver func(string) (string, error)) {
	interval := rm.config.reResolveInterval()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rm.CleanExpired()

				for _, name := range names {
					newValue, err := resolver(name)
					if err != nil {
						slog.Warn("secret rotation: failed to re-resolve secret",
							"name", name,
							"error", err.Error(),
						)
						continue
					}
					rm.Update(name, newValue)
				}
			}
		}
	}()
}
