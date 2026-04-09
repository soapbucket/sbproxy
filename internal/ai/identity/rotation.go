package identity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// RotationConfig configures key rotation behavior.
type RotationConfig struct {
	GracePeriod    time.Duration // How long old keys remain valid (default 24h).
	MaxGracePeriod time.Duration // Maximum allowed grace period (default 7 days).
	NotifyOnUse    bool          // Log warning when deprecated key is used.
}

func (c *RotationConfig) withDefaults() RotationConfig {
	out := *c
	if out.GracePeriod == 0 {
		out.GracePeriod = 24 * time.Hour
	}
	if out.MaxGracePeriod == 0 {
		out.MaxGracePeriod = 7 * 24 * time.Hour
	}
	// Clamp grace period to max.
	if out.GracePeriod > out.MaxGracePeriod {
		out.GracePeriod = out.MaxGracePeriod
	}
	return out
}

// DeprecatedKey tracks a rotated-out key.
type DeprecatedKey struct {
	OldHash      string    `json:"old_hash"`
	NewKeyID     string    `json:"new_key_id"`
	DeprecatedAt time.Time `json:"deprecated_at"`
	GraceEnds    time.Time `json:"grace_ends"`
	PrincipalID  string    `json:"principal_id"`
	UsageCount   atomic.Int64
}

// KeyRotator handles key rotation with grace periods.
type KeyRotator struct {
	mu            sync.RWMutex
	deprecated    map[string]*DeprecatedKey // old key hash -> DeprecatedKey
	config        RotationConfig
	authenticator Authenticator
	cache         *PermissionCache // Optional cache to invalidate.
	cleanupDone   chan struct{}
}

// NewKeyRotator creates a new KeyRotator wrapping the given authenticator.
// The cache parameter is optional and may be nil.
func NewKeyRotator(auth Authenticator, config RotationConfig, cache *PermissionCache) *KeyRotator {
	resolved := config.withDefaults()
	kr := &KeyRotator{
		deprecated:    make(map[string]*DeprecatedKey),
		config:        resolved,
		authenticator: auth,
		cache:         cache,
		cleanupDone:   make(chan struct{}),
	}
	go kr.backgroundCleanup()
	return kr
}

// Type implements the Authenticator interface, delegating to the underlying authenticator.
func (kr *KeyRotator) Type() CredentialType {
	return kr.authenticator.Type()
}

// RotateKey marks the old key as deprecated and associates it with the new key.
// The oldKeyHash is the SHA-256 hex digest of the old key. The newKeyID is an
// identifier (not hash) for the replacement key. The principalID links both keys
// to the same principal.
func (kr *KeyRotator) RotateKey(_ context.Context, oldKeyHash string, newKeyID string, principalID string) error {
	if oldKeyHash == "" {
		return fmt.Errorf("identity: old key hash cannot be empty")
	}
	if newKeyID == "" {
		return fmt.Errorf("identity: new key ID cannot be empty")
	}
	if principalID == "" {
		return fmt.Errorf("identity: principal ID cannot be empty")
	}

	now := time.Now()
	dk := &DeprecatedKey{
		OldHash:      oldKeyHash,
		NewKeyID:     newKeyID,
		DeprecatedAt: now,
		GraceEnds:    now.Add(kr.config.GracePeriod),
		PrincipalID:  principalID,
	}

	kr.mu.Lock()
	kr.deprecated[oldKeyHash] = dk
	kr.mu.Unlock()

	return nil
}

// Authenticate checks both current and deprecated keys.
// If a deprecated key is used during its grace period, authentication succeeds
// but a warning is logged (if NotifyOnUse is true). If the grace period has
// expired, authentication fails with a descriptive error.
func (kr *KeyRotator) Authenticate(ctx context.Context, credential string) (*Principal, error) {
	// Try the underlying authenticator first (normal path for current keys).
	p, err := kr.authenticator.Authenticate(ctx, credential)
	if err == nil {
		return p, nil
	}
	originalErr := err

	// Hash the credential and check the deprecated map.
	h := sha256.Sum256([]byte(credential))
	digest := fmt.Sprintf("%x", h)

	kr.mu.RLock()
	dk, found := kr.deprecated[digest]
	kr.mu.RUnlock()

	if !found {
		return nil, originalErr
	}

	// Found in deprecated set. Check grace period.
	now := time.Now()
	if now.After(dk.GraceEnds) {
		return nil, fmt.Errorf("identity: key expired, please use new key (grace period ended %s)", dk.GraceEnds.Format(time.RFC3339))
	}

	// Within grace period. Increment usage counter.
	dk.UsageCount.Add(1)

	if kr.config.NotifyOnUse {
		log.Printf("identity: deprecated key used for principal %s (new key: %s, grace ends: %s, usage: %d)",
			dk.PrincipalID, dk.NewKeyID, dk.GraceEnds.Format(time.RFC3339), dk.UsageCount.Load())
	}

	// Try to authenticate using the new key ID to get the principal.
	// The new key ID is the raw key value that the underlying authenticator knows about.
	newPrincipal, newErr := kr.authenticator.Authenticate(ctx, dk.NewKeyID)
	if newErr != nil {
		// If the new key also fails (e.g., it was removed), build a principal
		// from the deprecated key metadata as a fallback.
		return &Principal{
			ID:              dk.PrincipalID,
			Type:            kr.authenticator.Type(),
			AuthenticatedAt: now,
		}, nil
	}

	return newPrincipal, nil
}

// IsDeprecated checks if a key hash is in the deprecated set.
func (kr *KeyRotator) IsDeprecated(keyHash string) (*DeprecatedKey, bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	dk, ok := kr.deprecated[keyHash]
	return dk, ok
}

// RevokeDeprecated immediately revokes a deprecated key before its grace period ends.
func (kr *KeyRotator) RevokeDeprecated(_ context.Context, oldKeyHash string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if _, ok := kr.deprecated[oldKeyHash]; !ok {
		return fmt.Errorf("identity: key hash %s not found in deprecated set", oldKeyHash)
	}

	delete(kr.deprecated, oldKeyHash)

	// Invalidate cache if available.
	if kr.cache != nil {
		// Best-effort cache invalidation. We do not have the original credential,
		// only the hash, so we cannot build the exact cache key. The cache will
		// naturally expire via TTL.
	}

	return nil
}

// CleanupExpired removes deprecated keys whose grace period has passed.
func (kr *KeyRotator) CleanupExpired() {
	now := time.Now()
	kr.mu.Lock()
	defer kr.mu.Unlock()

	for hash, dk := range kr.deprecated {
		if now.After(dk.GraceEnds) {
			delete(kr.deprecated, hash)
		}
	}
}

// DeprecatedKeys returns all currently deprecated keys for monitoring.
func (kr *KeyRotator) DeprecatedKeys() []*DeprecatedKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	result := make([]*DeprecatedKey, 0, len(kr.deprecated))
	for _, dk := range kr.deprecated {
		result = append(result, dk)
	}
	return result
}

// Stop gracefully stops the background cleanup goroutine.
func (kr *KeyRotator) Stop() {
	select {
	case <-kr.cleanupDone:
		// Already stopped.
	default:
		close(kr.cleanupDone)
	}
}

// backgroundCleanup runs CleanupExpired every 5 minutes until Stop is called.
func (kr *KeyRotator) backgroundCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-kr.cleanupDone:
			return
		case <-ticker.C:
			kr.CleanupExpired()
		}
	}
}
