package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

func TestTokenBucket_Allow(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	tb := NewTokenBucket(cache, "test", 10, 1.0) // 10 tokens, 1 token/sec

	ctx := context.Background()
	key := "test-key"

	// Should allow first 10 requests immediately (burst)
	for i := 0; i < 10; i++ {
		result, err := tb.Allow(ctx, key, 10, time.Minute)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 11th request should be denied (no tokens left)
	result, err := tb.Allow(ctx, key, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("11th request should be denied")
	}

	// Wait for token refill
	time.Sleep(1100 * time.Millisecond)

	// Should allow one more request
	result, err = tb.Allow(ctx, key, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("request after refill should be allowed")
	}
}

func TestTokenBucket_AllowN(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	tb := NewTokenBucket(cache, "test", 10, 1.0)

	ctx := context.Background()
	key := "test-key"

	// Should allow 5 tokens
	result, err := tb.AllowN(ctx, key, 5, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("5 tokens should be allowed")
	}
	if result.Remaining != 5 {
		t.Errorf("expected remaining 5, got %d", result.Remaining)
	}

	// Should allow 5 more
	result, err = tb.AllowN(ctx, key, 5, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("5 more tokens should be allowed")
	}

	// Should deny 1 more (exceeds capacity)
	result, err = tb.AllowN(ctx, key, 1, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("should be denied when exceeding capacity")
	}
}

func TestTokenBucket_GetRemaining(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	tb := NewTokenBucket(cache, "test", 10, 1.0)

	ctx := context.Background()
	key := "test-key"

	// Initially should have 10 tokens
	remaining, err := tb.GetRemaining(ctx, key, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if remaining != 10 {
		t.Errorf("expected 10 remaining, got %d", remaining)
	}

	// Consume 3 tokens
	_, err = tb.AllowN(ctx, key, 3, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 7 remaining
	remaining, err = tb.GetRemaining(ctx, key, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if remaining != 7 {
		t.Errorf("expected 7 remaining, got %d", remaining)
	}
}

func TestTokenBucket_Reset(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	tb := NewTokenBucket(cache, "test", 10, 1.0)

	ctx := context.Background()
	key := "test-key"

	// Consume all tokens
	_, err := tb.AllowN(ctx, key, 10, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Reset
	err = tb.Reset(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have full capacity again
	remaining, err := tb.GetRemaining(ctx, key, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if remaining != 10 {
		t.Errorf("expected 10 remaining after reset, got %d", remaining)
	}
}

