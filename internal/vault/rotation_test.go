package vault

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewRotationManager(t *testing.T) {
	rm := NewRotationManager(DefaultRotationConfig())
	if rm == nil {
		t.Fatal("NewRotationManager returned nil")
	}
	if rm.config.GracePeriodSecs != 300 {
		t.Errorf("default GracePeriodSecs = %d, want 300", rm.config.GracePeriodSecs)
	}
	if rm.config.ReResolveIntervalSecs != 60 {
		t.Errorf("default ReResolveIntervalSecs = %d, want 60", rm.config.ReResolveIntervalSecs)
	}
}

func TestRotationManager_Update_NewSecret(t *testing.T) {
	rm := NewRotationManager(DefaultRotationConfig())

	rm.Update("API_KEY", "sk-first")

	val, ok := rm.Get("API_KEY")
	if !ok {
		t.Fatal("Get(API_KEY) returned false after Update")
	}
	if val != "sk-first" {
		t.Errorf("Get(API_KEY) = %q, want %q", val, "sk-first")
	}

	// No previous value should exist for a first-time insert.
	rm.mu.RLock()
	_, hasPrev := rm.previous["API_KEY"]
	rm.mu.RUnlock()
	if hasPrev {
		t.Error("expected no previous value for a new secret")
	}
}

func TestRotationManager_Update_Rotation(t *testing.T) {
	rm := NewRotationManager(RotationConfig{
		GracePeriodSecs:       10,
		ReResolveIntervalSecs: 1,
	})

	rm.Update("API_KEY", "sk-first")
	rm.Update("API_KEY", "sk-second")

	// Current should be the new value.
	val, ok := rm.Get("API_KEY")
	if !ok || val != "sk-second" {
		t.Errorf("current value = %q, want %q", val, "sk-second")
	}

	// Previous should be the old value.
	rm.mu.RLock()
	prev := rm.previous["API_KEY"]
	rm.mu.RUnlock()
	if prev != "sk-first" {
		t.Errorf("previous value = %q, want %q", prev, "sk-first")
	}
}

func TestRotationManager_Update_SameValue(t *testing.T) {
	rm := NewRotationManager(DefaultRotationConfig())

	rm.Update("API_KEY", "sk-same")
	rm.Update("API_KEY", "sk-same") // no-op

	rm.mu.RLock()
	_, hasPrev := rm.previous["API_KEY"]
	rm.mu.RUnlock()
	if hasPrev {
		t.Error("updating with same value should not create a previous entry")
	}
}

func TestRotationManager_Validate_Current(t *testing.T) {
	rm := NewRotationManager(DefaultRotationConfig())
	rm.Update("API_KEY", "sk-current")

	if !rm.Validate("API_KEY", "sk-current") {
		t.Error("Validate should return true for current value")
	}
	if rm.Validate("API_KEY", "sk-wrong") {
		t.Error("Validate should return false for incorrect value")
	}
}

func TestRotationManager_Validate_GracePeriod(t *testing.T) {
	rm := NewRotationManager(RotationConfig{
		GracePeriodSecs:       10, // 10 seconds grace
		ReResolveIntervalSecs: 1,
	})

	rm.Update("API_KEY", "sk-old")
	rm.Update("API_KEY", "sk-new")

	// Both old and new should be valid during grace period.
	if !rm.Validate("API_KEY", "sk-new") {
		t.Error("Validate should return true for current value")
	}
	if !rm.Validate("API_KEY", "sk-old") {
		t.Error("Validate should return true for grace-period value")
	}
}

func TestRotationManager_Validate_ExpiredGracePeriod(t *testing.T) {
	rm := NewRotationManager(RotationConfig{
		GracePeriodSecs:       1, // very short grace for testing
		ReResolveIntervalSecs: 1,
	})

	rm.Update("API_KEY", "sk-old")
	rm.Update("API_KEY", "sk-new")

	// Manually expire the grace period.
	rm.mu.Lock()
	rm.expiry["API_KEY"] = time.Now().Add(-1 * time.Second)
	rm.mu.Unlock()

	if rm.Validate("API_KEY", "sk-old") {
		t.Error("Validate should return false for expired grace-period value")
	}
	if !rm.Validate("API_KEY", "sk-new") {
		t.Error("Validate should still return true for current value")
	}
}

func TestRotationManager_Validate_NonExistent(t *testing.T) {
	rm := NewRotationManager(DefaultRotationConfig())

	if rm.Validate("MISSING", "any-value") {
		t.Error("Validate should return false for a non-existent secret")
	}
}

func TestRotationManager_CleanExpired(t *testing.T) {
	rm := NewRotationManager(RotationConfig{
		GracePeriodSecs:       1,
		ReResolveIntervalSecs: 1,
	})

	rm.Update("KEY_A", "old-a")
	rm.Update("KEY_A", "new-a")
	rm.Update("KEY_B", "old-b")
	rm.Update("KEY_B", "new-b")

	// Expire KEY_A but keep KEY_B valid.
	rm.mu.Lock()
	rm.expiry["KEY_A"] = time.Now().Add(-1 * time.Second)
	rm.expiry["KEY_B"] = time.Now().Add(10 * time.Second)
	rm.mu.Unlock()

	rm.CleanExpired()

	rm.mu.RLock()
	_, hasPrevA := rm.previous["KEY_A"]
	_, hasPrevB := rm.previous["KEY_B"]
	rm.mu.RUnlock()

	if hasPrevA {
		t.Error("KEY_A previous should have been cleaned")
	}
	if !hasPrevB {
		t.Error("KEY_B previous should still exist")
	}
}

func TestRotationManager_StartBackground(t *testing.T) {
	rm := NewRotationManager(RotationConfig{
		GracePeriodSecs:       300,
		ReResolveIntervalSecs: 1, // poll every second for test speed
	})

	// Seed initial value.
	rm.Update("API_KEY", "sk-v1")

	// Mock resolver that returns an updated value after the first call.
	var mu sync.Mutex
	callCount := 0
	resolver := func(name string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		if callCount >= 2 {
			return "sk-v2", nil
		}
		return "sk-v1", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rm.StartBackground(ctx, []string{"API_KEY"}, resolver)

	// Wait for at least two ticks.
	time.Sleep(3 * time.Second)
	cancel()

	// Should have rotated to v2.
	val, ok := rm.Get("API_KEY")
	if !ok {
		t.Fatal("Get(API_KEY) returned false after background rotation")
	}
	if val != "sk-v2" {
		t.Errorf("Get(API_KEY) = %q, want %q", val, "sk-v2")
	}

	// v1 should still be valid in grace period.
	if !rm.Validate("API_KEY", "sk-v1") {
		t.Error("old value should still be valid during grace period")
	}
}

func TestRotationManager_StartBackground_ResolverError(t *testing.T) {
	rm := NewRotationManager(RotationConfig{
		GracePeriodSecs:       300,
		ReResolveIntervalSecs: 1,
	})

	rm.Update("API_KEY", "sk-original")

	resolver := func(name string) (string, error) {
		return "", fmt.Errorf("vault unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rm.StartBackground(ctx, []string{"API_KEY"}, resolver)

	// Wait for a couple of ticks.
	time.Sleep(2500 * time.Millisecond)
	cancel()

	// Value should remain unchanged despite resolver errors.
	val, ok := rm.Get("API_KEY")
	if !ok || val != "sk-original" {
		t.Errorf("Get(API_KEY) = %q, want %q (should be unchanged on error)", val, "sk-original")
	}
}

func TestRotationManager_StartBackground_ContextCancellation(t *testing.T) {
	rm := NewRotationManager(RotationConfig{
		GracePeriodSecs:       300,
		ReResolveIntervalSecs: 1,
	})

	var mu sync.Mutex
	callCount := 0
	resolver := func(name string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		return "value", nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	rm.StartBackground(ctx, []string{"KEY"}, resolver)

	// Cancel immediately.
	cancel()

	// Wait briefly, then verify no further calls.
	time.Sleep(2 * time.Second)
	mu.Lock()
	count := callCount
	mu.Unlock()

	// At most 1 call may have sneaked through before cancellation.
	if count > 1 {
		t.Errorf("resolver called %d times after cancellation, expected at most 1", count)
	}
}

func TestRotationManager_ConcurrentAccess(t *testing.T) {
	rm := NewRotationManager(RotationConfig{
		GracePeriodSecs:       10,
		ReResolveIntervalSecs: 1,
	})

	var wg sync.WaitGroup
	const goroutines = 50
	const iterations = 100

	// Concurrent writers.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				rm.Update("KEY", fmt.Sprintf("value-%d-%d", id, j))
			}
		}(i)
	}

	// Concurrent readers.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				rm.Validate("KEY", "some-value")
				rm.Get("KEY")
				rm.CleanExpired()
			}
		}()
	}

	wg.Wait()
}

func TestRotationConfig_Defaults(t *testing.T) {
	// Zero-value config should use defaults.
	cfg := RotationConfig{}
	if cfg.gracePeriod() != 300*time.Second {
		t.Errorf("gracePeriod() = %v, want 300s", cfg.gracePeriod())
	}
	if cfg.reResolveInterval() != 60*time.Second {
		t.Errorf("reResolveInterval() = %v, want 60s", cfg.reResolveInterval())
	}
}
