package identity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"
)

// mockAuthenticator is a test double that authenticates keys from a static map.
type mockAuthenticator struct {
	keys map[string]*Principal // raw key -> principal
	typ  CredentialType
}

func (m *mockAuthenticator) Type() CredentialType { return m.typ }

func (m *mockAuthenticator) Authenticate(_ context.Context, credential string) (*Principal, error) {
	if p, ok := m.keys[credential]; ok {
		cp := *p
		cp.AuthenticatedAt = time.Now()
		return &cp, nil
	}
	return nil, fmt.Errorf("identity: invalid key")
}

func newMockAuth(keys map[string]*Principal) *mockAuthenticator {
	return &mockAuthenticator{keys: keys, typ: CredentialAPIKey}
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h)
}

func TestKeyRotator_NormalAuth(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{
		"current-key": {ID: "user-1", Type: CredentialAPIKey},
	})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)
	defer kr.Stop()

	p, err := kr.Authenticate(context.Background(), "current-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ID != "user-1" {
		t.Errorf("expected user-1, got %s", p.ID)
	}
}

func TestKeyRotator_DeprecatedKeyDuringGrace(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{
		"new-key": {ID: "user-1", Type: CredentialAPIKey},
	})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)
	defer kr.Stop()

	oldHash := hashKey("old-key")
	err := kr.RotateKey(context.Background(), oldHash, "new-key", "user-1")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Old key should still work during grace period.
	p, err := kr.Authenticate(context.Background(), "old-key")
	if err != nil {
		t.Fatalf("deprecated key during grace should authenticate: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.ID != "user-1" {
		t.Errorf("expected user-1, got %s", p.ID)
	}
}

func TestKeyRotator_DeprecatedKeyAfterGrace(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{
		"new-key": {ID: "user-1", Type: CredentialAPIKey},
	})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Millisecond}, nil)
	defer kr.Stop()

	oldHash := hashKey("old-key")
	err := kr.RotateKey(context.Background(), oldHash, "new-key", "user-1")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Wait for grace period to expire.
	time.Sleep(5 * time.Millisecond)

	_, err = kr.Authenticate(context.Background(), "old-key")
	if err == nil {
		t.Error("expected error for deprecated key after grace period")
	}
}

func TestKeyRotator_RotateKey(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)
	defer kr.Stop()

	oldHash := hashKey("key-to-rotate")
	err := kr.RotateKey(context.Background(), oldHash, "replacement-key", "principal-1")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	dk, found := kr.IsDeprecated(oldHash)
	if !found {
		t.Fatal("expected key to be in deprecated set")
	}
	if dk.PrincipalID != "principal-1" {
		t.Errorf("expected principal-1, got %s", dk.PrincipalID)
	}
	if dk.NewKeyID != "replacement-key" {
		t.Errorf("expected replacement-key, got %s", dk.NewKeyID)
	}
}

func TestKeyRotator_RotateKey_Validation(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{})
	kr := NewKeyRotator(auth, RotationConfig{}, nil)
	defer kr.Stop()

	tests := []struct {
		name        string
		oldHash     string
		newKeyID    string
		principalID string
	}{
		{"empty old hash", "", "new", "p1"},
		{"empty new key ID", "old", "", "p1"},
		{"empty principal ID", "old", "new", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := kr.RotateKey(context.Background(), tt.oldHash, tt.newKeyID, tt.principalID)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestKeyRotator_RevokeEarly(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{
		"new-key": {ID: "user-1", Type: CredentialAPIKey},
	})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)
	defer kr.Stop()

	oldHash := hashKey("old-key")
	err := kr.RotateKey(context.Background(), oldHash, "new-key", "user-1")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Revoke early.
	err = kr.RevokeDeprecated(context.Background(), oldHash)
	if err != nil {
		t.Fatalf("RevokeDeprecated failed: %v", err)
	}

	// Old key should no longer work (not found in deprecated, not in current).
	_, err = kr.Authenticate(context.Background(), "old-key")
	if err == nil {
		t.Error("expected error after early revocation")
	}

	// Revoking again should fail.
	err = kr.RevokeDeprecated(context.Background(), oldHash)
	if err == nil {
		t.Error("expected error revoking non-existent key")
	}
}

func TestKeyRotator_UsageTracking(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{
		"new-key": {ID: "user-1", Type: CredentialAPIKey},
	})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour, NotifyOnUse: true}, nil)
	defer kr.Stop()

	oldHash := hashKey("old-key")
	err := kr.RotateKey(context.Background(), oldHash, "new-key", "user-1")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Use the old key multiple times.
	for i := 0; i < 5; i++ {
		_, err := kr.Authenticate(context.Background(), "old-key")
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
	}

	dk, found := kr.IsDeprecated(oldHash)
	if !found {
		t.Fatal("expected key in deprecated set")
	}
	if dk.UsageCount.Load() != 5 {
		t.Errorf("expected usage count 5, got %d", dk.UsageCount.Load())
	}
}

func TestKeyRotator_CleanupExpired(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Millisecond}, nil)
	defer kr.Stop()

	hash1 := hashKey("expired-key-1")
	hash2 := hashKey("expired-key-2")

	err := kr.RotateKey(context.Background(), hash1, "new-1", "p1")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
	err = kr.RotateKey(context.Background(), hash2, "new-2", "p2")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Wait for grace to expire.
	time.Sleep(5 * time.Millisecond)

	kr.CleanupExpired()

	keys := kr.DeprecatedKeys()
	if len(keys) != 0 {
		t.Errorf("expected 0 deprecated keys after cleanup, got %d", len(keys))
	}
}

func TestKeyRotator_ConcurrentAuth(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{
		"current-key": {ID: "user-1", Type: CredentialAPIKey},
		"new-key":     {ID: "user-2", Type: CredentialAPIKey},
	})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)
	defer kr.Stop()

	oldHash := hashKey("old-key")
	err := kr.RotateKey(context.Background(), oldHash, "new-key", "user-2")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	// Run concurrent authentications with both current and deprecated keys.
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := kr.Authenticate(context.Background(), "current-key")
			if err != nil {
				errs <- fmt.Errorf("current-key auth failed: %w", err)
			}
		}()
		go func() {
			defer wg.Done()
			_, err := kr.Authenticate(context.Background(), "old-key")
			if err != nil {
				errs <- fmt.Errorf("old-key auth failed: %w", err)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestKeyRotator_NilCache(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{
		"key-1": {ID: "user-1", Type: CredentialAPIKey},
	})
	// Explicitly pass nil cache.
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)
	defer kr.Stop()

	p, err := kr.Authenticate(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ID != "user-1" {
		t.Errorf("expected user-1, got %s", p.ID)
	}

	// Rotation and revocation should also work without cache.
	oldHash := hashKey("key-1")
	err = kr.RotateKey(context.Background(), oldHash, "key-2", "user-1")
	if err != nil {
		t.Fatalf("RotateKey with nil cache failed: %v", err)
	}
	err = kr.RevokeDeprecated(context.Background(), oldHash)
	if err != nil {
		t.Fatalf("RevokeDeprecated with nil cache failed: %v", err)
	}
}

func TestKeyRotator_MaxGracePeriod(t *testing.T) {
	// Grace period exceeds max, should be clamped.
	kr := NewKeyRotator(
		newMockAuth(map[string]*Principal{}),
		RotationConfig{
			GracePeriod:    30 * 24 * time.Hour, // 30 days
			MaxGracePeriod: 7 * 24 * time.Hour,  // 7 days max
		},
		nil,
	)
	defer kr.Stop()

	if kr.config.GracePeriod != 7*24*time.Hour {
		t.Errorf("expected grace period clamped to 7 days, got %v", kr.config.GracePeriod)
	}
}

func TestKeyRotator_MultipleRotations(t *testing.T) {
	// Chain: key1 -> key2 -> key3
	auth := newMockAuth(map[string]*Principal{
		"key-3": {ID: "user-1", Type: CredentialAPIKey},
	})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)
	defer kr.Stop()

	// Rotate key1 -> key2
	hash1 := hashKey("key-1")
	err := kr.RotateKey(context.Background(), hash1, "key-2", "user-1")
	if err != nil {
		t.Fatalf("RotateKey key1->key2 failed: %v", err)
	}

	// Rotate key2 -> key3
	hash2 := hashKey("key-2")
	err = kr.RotateKey(context.Background(), hash2, "key-3", "user-1")
	if err != nil {
		t.Fatalf("RotateKey key2->key3 failed: %v", err)
	}

	// key3 (current) should work.
	p, err := kr.Authenticate(context.Background(), "key-3")
	if err != nil {
		t.Fatalf("key-3 auth failed: %v", err)
	}
	if p.ID != "user-1" {
		t.Errorf("expected user-1, got %s", p.ID)
	}

	// key2 (deprecated, grace active, new key is key-3 which is current) should work.
	p, err = kr.Authenticate(context.Background(), "key-2")
	if err != nil {
		t.Fatalf("key-2 auth during grace failed: %v", err)
	}
	if p.ID != "user-1" {
		t.Errorf("expected user-1, got %s", p.ID)
	}

	// key1 (deprecated, grace active, new key is key-2 which is also deprecated).
	// key-2 is not in the underlying auth, so it will fall back to principal metadata.
	p, err = kr.Authenticate(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("key-1 auth during grace failed: %v", err)
	}
	if p.ID != "user-1" {
		t.Errorf("expected user-1, got %s", p.ID)
	}

	// Verify both are in deprecated set.
	keys := kr.DeprecatedKeys()
	if len(keys) != 2 {
		t.Errorf("expected 2 deprecated keys, got %d", len(keys))
	}
}

func TestKeyRotator_IsDeprecated(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)
	defer kr.Stop()

	hash := hashKey("some-key")

	// Not deprecated yet.
	_, found := kr.IsDeprecated(hash)
	if found {
		t.Error("key should not be deprecated yet")
	}

	// Deprecate it.
	err := kr.RotateKey(context.Background(), hash, "new-key", "p1")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	dk, found := kr.IsDeprecated(hash)
	if !found {
		t.Fatal("expected key to be deprecated")
	}
	if dk.OldHash != hash {
		t.Errorf("expected hash %s, got %s", hash, dk.OldHash)
	}
}

func TestKeyRotator_DeprecatedKeys(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)
	defer kr.Stop()

	// Empty initially.
	if len(kr.DeprecatedKeys()) != 0 {
		t.Error("expected empty deprecated keys initially")
	}

	// Add some.
	for i := 0; i < 3; i++ {
		hash := hashKey(fmt.Sprintf("key-%d", i))
		err := kr.RotateKey(context.Background(), hash, fmt.Sprintf("new-%d", i), fmt.Sprintf("p-%d", i))
		if err != nil {
			t.Fatalf("RotateKey failed: %v", err)
		}
	}

	keys := kr.DeprecatedKeys()
	if len(keys) != 3 {
		t.Errorf("expected 3 deprecated keys, got %d", len(keys))
	}
}

func TestKeyRotator_Stop(t *testing.T) {
	auth := newMockAuth(map[string]*Principal{
		"key-1": {ID: "user-1", Type: CredentialAPIKey},
	})
	kr := NewKeyRotator(auth, RotationConfig{GracePeriod: time.Hour}, nil)

	// Stop should not panic.
	kr.Stop()

	// Double stop should not panic.
	kr.Stop()

	// Auth should still work after stop (only background cleanup is stopped).
	p, err := kr.Authenticate(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("auth after stop failed: %v", err)
	}
	if p.ID != "user-1" {
		t.Errorf("expected user-1, got %s", p.ID)
	}
}
