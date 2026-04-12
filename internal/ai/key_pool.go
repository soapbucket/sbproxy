// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// KeyPool provides round-robin selection across multiple API keys for a single
// provider, with per-key circuit breaking to remove failed keys from rotation.
type KeyPool struct {
	mu        sync.RWMutex
	keys      []poolKey
	index     atomic.Uint64
	threshold int           // consecutive failures before disabling a key
	cooldown  time.Duration // how long a failed key stays disabled
}

type poolKey struct {
	value      string
	failures   int
	disabledAt time.Time
}

// NewKeyPool creates a pool from a list of API keys. If a single key is provided,
// it operates in single-key compatibility mode (no rotation).
// threshold is the number of consecutive failures before a key is removed from
// rotation. cooldown is how long a disabled key stays out of rotation.
func NewKeyPool(apiKeys []string, threshold int, cooldown time.Duration) (*KeyPool, error) {
	if len(apiKeys) == 0 {
		return nil, fmt.Errorf("key_pool: at least one API key is required")
	}
	if threshold <= 0 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = 60 * time.Second
	}

	keys := make([]poolKey, len(apiKeys))
	for i, k := range apiKeys {
		keys[i] = poolKey{value: k}
	}

	return &KeyPool{
		keys:      keys,
		threshold: threshold,
		cooldown:  cooldown,
	}, nil
}

// Next returns the next available API key using round-robin selection.
// Keys that have exceeded the failure threshold and are still within the
// cooldown period are skipped.
func (kp *KeyPool) Next() (string, error) {
	kp.mu.RLock()
	totalKeys := len(kp.keys)
	kp.mu.RUnlock()

	if totalKeys == 0 {
		return "", fmt.Errorf("key_pool: no keys configured")
	}

	now := time.Now()
	startIdx := kp.index.Add(1) - 1

	// Try all keys starting from the current index.
	for i := 0; i < totalKeys; i++ {
		idx := int((startIdx + uint64(i)) % uint64(totalKeys))

		kp.mu.RLock()
		k := kp.keys[idx]
		kp.mu.RUnlock()

		// Check if key is disabled.
		if k.failures >= kp.threshold {
			if now.Before(k.disabledAt.Add(kp.cooldown)) {
				continue // still in cooldown
			}
			// Cooldown expired, re-enable key.
			kp.mu.Lock()
			kp.keys[idx].failures = 0
			kp.keys[idx].disabledAt = time.Time{}
			kp.mu.Unlock()
		}

		return k.value, nil
	}

	return "", fmt.Errorf("key_pool: all keys are in cooldown")
}

// ReportFailure records a failure for the given key. After reaching the
// threshold, the key is removed from active rotation for the cooldown period.
func (kp *KeyPool) ReportFailure(apiKey string) {
	kp.mu.Lock()
	defer kp.mu.Unlock()

	for i := range kp.keys {
		if kp.keys[i].value == apiKey {
			kp.keys[i].failures++
			if kp.keys[i].failures >= kp.threshold {
				kp.keys[i].disabledAt = time.Now()
			}
			return
		}
	}
}

// ReportSuccess resets the failure count for a key.
func (kp *KeyPool) ReportSuccess(apiKey string) {
	kp.mu.Lock()
	defer kp.mu.Unlock()

	for i := range kp.keys {
		if kp.keys[i].value == apiKey {
			kp.keys[i].failures = 0
			kp.keys[i].disabledAt = time.Time{}
			return
		}
	}
}

// Size returns the total number of keys in the pool.
func (kp *KeyPool) Size() int {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	return len(kp.keys)
}

// ActiveCount returns the number of keys currently available for selection.
func (kp *KeyPool) ActiveCount() int {
	kp.mu.RLock()
	defer kp.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, k := range kp.keys {
		if k.failures < kp.threshold || now.After(k.disabledAt.Add(kp.cooldown)) {
			count++
		}
	}
	return count
}

// ResolveAPIKey returns a key from the pool if configured, otherwise returns
// the single key. This integrates with ProviderConfig's existing api_key field.
func ResolveAPIKey(cfg *ProviderConfig, pool *KeyPool) (string, error) {
	if pool != nil {
		return pool.Next()
	}
	if cfg.APIKey != "" {
		return cfg.APIKey, nil
	}
	return "", fmt.Errorf("no API key configured for provider %s", cfg.Name)
}
