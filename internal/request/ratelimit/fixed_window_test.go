package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

func TestFixedWindow_Allow(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	fw := NewFixedWindow(cache, "test")

	ctx := context.Background()
	key := "test-key"
	limit := 10
	window := time.Minute

	// Should allow first 10 requests
	for i := 0; i < 10; i++ {
		result, err := fw.Allow(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 11th request should be denied
	result, err := fw.Allow(ctx, key, limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("11th request should be denied")
	}
}

func TestFixedWindow_AllowN(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	fw := NewFixedWindow(cache, "test")

	ctx := context.Background()
	key := "test-key"

	// Should allow 5 requests
	result, err := fw.AllowN(ctx, key, 5, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("5 requests should be allowed")
	}
	if result.Remaining != 5 {
		t.Errorf("expected remaining 5, got %d", result.Remaining)
	}

	// Should allow 5 more
	result, err = fw.AllowN(ctx, key, 5, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("5 more requests should be allowed")
	}

	// Should deny 1 more
	result, err = fw.AllowN(ctx, key, 1, 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("should be denied when exceeding limit")
	}
}

func TestFixedWindow_WindowReset(t *testing.T) {
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: "memory", MaxObjects: 1000})
	fw := NewFixedWindow(cache, "test")

	ctx := context.Background()
	key := "test-key"
	limit := 10
	window := 2 * time.Second // Short window for testing

	// Consume all requests
	for i := 0; i < 10; i++ {
		_, err := fw.Allow(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Should be denied
	result, err := fw.Allow(ctx, key, limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("should be denied")
	}

	// Wait for window to reset
	time.Sleep(2100 * time.Millisecond)

	// Should allow requests again
	result, err = fw.Allow(ctx, key, limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("should be allowed after window reset")
	}
}

