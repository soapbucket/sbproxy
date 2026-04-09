package ai

import (
	"testing"
	"time"
)

func TestKeyPool_RoundRobin(t *testing.T) {
	pool, err := NewKeyPool([]string{"key-a", "key-b", "key-c"}, 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// Should cycle through keys in round-robin order.
	seen := make(map[string]int)
	for i := 0; i < 9; i++ {
		key, err := pool.Next()
		if err != nil {
			t.Fatalf("unexpected error on call %d: %v", i, err)
		}
		seen[key]++
	}

	// Each key should be selected 3 times.
	for _, k := range []string{"key-a", "key-b", "key-c"} {
		if seen[k] != 3 {
			t.Errorf("expected key %s selected 3 times, got %d", k, seen[k])
		}
	}
}

func TestKeyPool_SingleKeyCompat(t *testing.T) {
	pool, err := NewKeyPool([]string{"only-key"}, 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		key, err := pool.Next()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "only-key" {
			t.Errorf("expected 'only-key', got %q", key)
		}
	}
}

func TestKeyPool_FailureRemoval(t *testing.T) {
	pool, err := NewKeyPool([]string{"key-a", "key-b"}, 2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// Fail key-a twice (reaches threshold).
	pool.ReportFailure("key-a")
	pool.ReportFailure("key-a")

	// All selections should return key-b now.
	for i := 0; i < 5; i++ {
		key, err := pool.Next()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "key-b" {
			t.Errorf("expected 'key-b', got %q (key-a should be disabled)", key)
		}
	}

	if pool.ActiveCount() != 1 {
		t.Errorf("expected 1 active key, got %d", pool.ActiveCount())
	}
}

func TestKeyPool_SuccessResetsFailures(t *testing.T) {
	pool, err := NewKeyPool([]string{"key-a", "key-b"}, 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	pool.ReportFailure("key-a")
	pool.ReportFailure("key-a")
	// 2 failures, still below threshold of 3
	pool.ReportSuccess("key-a")

	// key-a should still be active
	if pool.ActiveCount() != 2 {
		t.Errorf("expected 2 active keys, got %d", pool.ActiveCount())
	}
}

func TestKeyPool_AllKeysDisabled(t *testing.T) {
	pool, err := NewKeyPool([]string{"key-a", "key-b"}, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	pool.ReportFailure("key-a")
	pool.ReportFailure("key-b")

	_, err = pool.Next()
	if err == nil {
		t.Fatal("expected error when all keys are disabled")
	}
}

func TestKeyPool_CooldownRecovery(t *testing.T) {
	pool, err := NewKeyPool([]string{"key-a"}, 1, 1*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	pool.ReportFailure("key-a")

	// Wait for cooldown to expire.
	time.Sleep(5 * time.Millisecond)

	key, err := pool.Next()
	if err != nil {
		t.Fatalf("expected key to recover after cooldown: %v", err)
	}
	if key != "key-a" {
		t.Errorf("expected key-a, got %q", key)
	}
}

func TestKeyPool_EmptyKeysError(t *testing.T) {
	_, err := NewKeyPool(nil, 3, time.Minute)
	if err == nil {
		t.Fatal("expected error for empty keys")
	}

	_, err = NewKeyPool([]string{}, 3, time.Minute)
	if err == nil {
		t.Fatal("expected error for empty keys")
	}
}

func TestResolveAPIKey_WithPool(t *testing.T) {
	pool, _ := NewKeyPool([]string{"pool-key"}, 3, time.Minute)
	cfg := &ProviderConfig{Name: "test", APIKey: "single-key"}

	key, err := ResolveAPIKey(cfg, pool)
	if err != nil {
		t.Fatal(err)
	}
	if key != "pool-key" {
		t.Errorf("expected pool-key, got %q", key)
	}
}

func TestResolveAPIKey_WithoutPool(t *testing.T) {
	cfg := &ProviderConfig{Name: "test", APIKey: "single-key"}

	key, err := ResolveAPIKey(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if key != "single-key" {
		t.Errorf("expected single-key, got %q", key)
	}
}

func TestResolveAPIKey_NoKey(t *testing.T) {
	cfg := &ProviderConfig{Name: "test"}
	_, err := ResolveAPIKey(cfg, nil)
	if err == nil {
		t.Fatal("expected error when no key configured")
	}
}
