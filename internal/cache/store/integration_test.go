package cacher

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestIntegration(t *testing.T) {
	t.Parallel()
	// Test only the noop manager since it's always available
	settings := Settings{
		Driver: "noop",
	}
	manager, err := NewCacher(settings)
	if err != nil {
		t.Fatalf("Failed to create noop manager: %v", err)
	}
	defer manager.Close()

	ctx := context.Background()

	// Test basic operations
	err = manager.Put(ctx, "test-type", "test-key", bytes.NewReader([]byte("test-value")))
	if err != nil {
		t.Errorf("Put failed: %v", err)
	}

	// Noop manager doesn't store data, so Get should return ErrNotFound
	_, err = manager.Get(ctx, "test-type", "test-key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for noop manager, got %v", err)
	}

	// Test increment
	count, err := manager.Increment(ctx, "test-type", "counter", 5)
	if err != nil {
		t.Errorf("Increment failed: %v", err)
	}
	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}

	// Test expiration
	err = manager.PutWithExpires(ctx, "test-type", "expired-key", bytes.NewReader([]byte("expired-value")), 50*time.Millisecond)
	if err != nil {
		t.Errorf("PutWithExpires failed: %v", err)
	}

	// Noop manager doesn't store data, so Get should return ErrNotFound
	_, err = manager.Get(ctx, "test-type", "expired-key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for noop manager, got %v", err)
	}

	// Test delete by pattern
	err = manager.Put(ctx, "test-type", "prefix_key1", bytes.NewReader([]byte("value1")))
	if err != nil {
		t.Errorf("Put prefix_key1 failed: %v", err)
	}

	err = manager.Put(ctx, "test-type", "prefix_key2", bytes.NewReader([]byte("value2")))
	if err != nil {
		t.Errorf("Put prefix_key2 failed: %v", err)
	}

	err = manager.Put(ctx, "test-type", "other_key", bytes.NewReader([]byte("value")))
	if err != nil {
		t.Errorf("Put other_key failed: %v", err)
	}

	err = manager.DeleteByPattern(ctx, "test-type", "prefix_")
	if err != nil {
		t.Errorf("DeleteByPattern failed: %v", err)
	}

	// Noop manager doesn't store data, so all Gets should return ErrNotFound
	_, err = manager.Get(ctx, "test-type", "prefix_key1")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for noop manager")
	}

	_, err = manager.Get(ctx, "test-type", "prefix_key2")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for noop manager")
	}

	_, err = manager.Get(ctx, "test-type", "other_key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for noop manager")
	}
}
