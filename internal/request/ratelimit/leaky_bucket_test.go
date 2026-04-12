package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

func TestLeakyBucket_Allow(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	lb := NewLeakyBucket(cache, "test", 10, 1.0) // Queue size 10, drain rate 1 req/sec

	ctx := context.Background()
	key := "test-key"

	// Should allow first 10 requests (queue capacity)
	for i := 0; i < 10; i++ {
		result, err := lb.Allow(ctx, key, 10, time.Minute)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 11th request should be denied (queue full)
	result, err := lb.Allow(ctx, key, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("11th request should be denied")
	}

	// Wait for queue to drain
	time.Sleep(1100 * time.Millisecond)

	// Should allow one more request
	result, err = lb.Allow(ctx, key, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("request after drain should be allowed")
	}
}

func TestLeakyBucket_AllowN(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	lb := NewLeakyBucket(cache, "test", 10, 1.0)

	ctx := context.Background()
	key := "test-key"

	// Should allow 5 requests
	result, err := lb.AllowN(ctx, key, 5, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("5 requests should be allowed")
	}

	// Should allow 5 more
	result, err = lb.AllowN(ctx, key, 5, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("5 more requests should be allowed")
	}

	// Should deny 1 more (exceeds queue size)
	result, err = lb.AllowN(ctx, key, 1, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("should be denied when exceeding queue size")
	}
}

func TestLeakyBucket_GetRemaining(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	lb := NewLeakyBucket(cache, "test", 10, 1.0)

	ctx := context.Background()
	key := "test-key"

	// Initially should have full queue capacity
	remaining, err := lb.GetRemaining(ctx, key, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if remaining != 10 {
		t.Errorf("expected 10 remaining, got %d", remaining)
	}

	// Add 3 to queue
	_, err = lb.AllowN(ctx, key, 3, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 7 remaining
	remaining, err = lb.GetRemaining(ctx, key, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if remaining != 7 {
		t.Errorf("expected 7 remaining, got %d", remaining)
	}
}
