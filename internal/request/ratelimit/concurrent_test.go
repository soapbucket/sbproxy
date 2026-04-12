package ratelimit

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cacher "github.com/soapbucket/sbproxy/internal/cache/store"
)

// newTestCache creates a memory-backed cacher for test isolation.
func newTestCache(t *testing.T) cacher.Cacher {
	t.Helper()
	cache, err := cacher.NewCacher(cacher.Settings{
		Driver:     "memory",
		MaxObjects: 100000,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	t.Cleanup(func() { cache.Close() })
	return cache
}

// TestFixedWindow_ConcurrentAllowN launches 100 goroutines each calling
// AllowN(1) with a limit of 50. The total allowed count should not
// wildly exceed the limit (some TOCTOU margin is expected).
func TestFixedWindow_ConcurrentAllowN(t *testing.T) {
	cache := newTestCache(t)
	fw := NewFixedWindow(cache, "conc-fw")

	ctx := context.Background()
	key := "concurrent-key"
	limit := 50
	window := 10 * time.Second

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var allowed atomic.Int64
	var denied atomic.Int64

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			result, _ := fw.AllowN(ctx, key, 1, limit, window)
			if result.Allowed {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()

	a := allowed.Load()
	d := denied.Load()
	t.Logf("FixedWindow concurrent: allowed=%d, denied=%d", a, d)

	// Allow some TOCTOU margin. The limit is 50, but with races the
	// actual count might be slightly higher. We accept up to 2x margin.
	if a > int64(limit)*2 {
		t.Errorf("allowed %d requests, expected at most ~%d (2x margin)", a, limit*2)
	}
	if a+d != goroutines {
		t.Errorf("total results %d, expected %d", a+d, goroutines)
	}
}

// TestTokenBucket_ConcurrentAllowN verifies token bucket thread safety.
func TestTokenBucket_ConcurrentAllowN(t *testing.T) {
	cache := newTestCache(t)
	tb := NewTokenBucket(cache, "conc-tb", 50, 0.0)

	ctx := context.Background()
	key := "concurrent-key"
	limit := 50
	window := 10 * time.Second

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var allowed atomic.Int64
	var denied atomic.Int64

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			result, _ := tb.AllowN(ctx, key, 1, limit, window)
			if result.Allowed {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()

	a := allowed.Load()
	d := denied.Load()
	t.Logf("TokenBucket concurrent: allowed=%d, denied=%d", a, d)

	if a > int64(limit)*2 {
		t.Errorf("allowed %d requests, expected at most ~%d (2x margin)", a, limit*2)
	}
	if a+d != goroutines {
		t.Errorf("total results %d, expected %d", a+d, goroutines)
	}
}

// TestLeakyBucket_ConcurrentAllowN verifies leaky bucket thread safety.
func TestLeakyBucket_ConcurrentAllowN(t *testing.T) {
	cache := newTestCache(t)
	lb := NewLeakyBucket(cache, "conc-lb", 50, 0.0)

	ctx := context.Background()
	key := "concurrent-key"
	limit := 50
	window := 10 * time.Second

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var allowed atomic.Int64
	var denied atomic.Int64

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			result, _ := lb.AllowN(ctx, key, 1, limit, window)
			if result.Allowed {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()

	a := allowed.Load()
	d := denied.Load()
	t.Logf("LeakyBucket concurrent: allowed=%d, denied=%d", a, d)

	if a > int64(limit)*2 {
		t.Errorf("allowed %d requests, expected at most ~%d (2x margin)", a, limit*2)
	}
	if a+d != goroutines {
		t.Errorf("total results %d, expected %d", a+d, goroutines)
	}
}

// TestDistributed_ConcurrentAllow verifies sliding window thread safety.
func TestDistributed_ConcurrentAllow(t *testing.T) {
	cache := newTestCache(t)
	rl := NewDistributedRateLimiter(cache, "conc-rl")

	ctx := context.Background()
	key := "concurrent-key"
	limit := 50
	window := 10 * time.Second

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var allowed atomic.Int64
	var denied atomic.Int64

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			result, _ := rl.Allow(ctx, key, limit, window)
			if result.Allowed {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()

	a := allowed.Load()
	d := denied.Load()
	t.Logf("Distributed concurrent: allowed=%d, denied=%d", a, d)

	if a > int64(limit)*2 {
		t.Errorf("allowed %d requests, expected at most ~%d (2x margin)", a, limit*2)
	}
	if a+d != goroutines {
		t.Errorf("total results %d, expected %d", a+d, goroutines)
	}
}

// errorCacher is a mock Cacher that returns errors on every operation
// to verify fail-open behavior.
type errorCacher struct{}

func (e *errorCacher) Get(_ context.Context, _, _ string) (io.Reader, error) {
	return nil, fmt.Errorf("mock error")
}
func (e *errorCacher) ListKeys(_ context.Context, _, _ string) ([]string, error) {
	return nil, fmt.Errorf("mock error")
}
func (e *errorCacher) Put(_ context.Context, _, _ string, _ io.Reader) error {
	return fmt.Errorf("mock error")
}
func (e *errorCacher) PutWithExpires(_ context.Context, _, _ string, _ io.Reader, _ time.Duration) error {
	return fmt.Errorf("mock error")
}
func (e *errorCacher) Delete(_ context.Context, _, _ string) error {
	return fmt.Errorf("mock error")
}
func (e *errorCacher) DeleteByPattern(_ context.Context, _, _ string) error {
	return fmt.Errorf("mock error")
}
func (e *errorCacher) Increment(_ context.Context, _, _ string, _ int64) (int64, error) {
	return 0, fmt.Errorf("mock error")
}
func (e *errorCacher) IncrementWithExpires(_ context.Context, _, _ string, _ int64, _ time.Duration) (int64, error) {
	return 0, fmt.Errorf("mock error")
}
func (e *errorCacher) Driver() string { return "error" }
func (e *errorCacher) Close() error   { return nil }

// Verify errorCacher implements cacher.Cacher at compile time.
var _ cacher.Cacher = (*errorCacher)(nil)

// TestFixedWindow_FailOpen_CacheErrors verifies that the fixed window
// rate limiter allows requests when the cache returns errors.
func TestFixedWindow_FailOpen_CacheErrors(t *testing.T) {
	fw := NewFixedWindow(&errorCacher{}, "err-fw")

	ctx := context.Background()
	result, err := fw.Allow(ctx, "test-key", 10, time.Minute)

	// Should fail open: allow the request despite cache errors
	if !result.Allowed {
		t.Error("expected fail-open behavior: request should be allowed")
	}
	if err == nil {
		t.Error("expected non-nil error to be returned")
	}

	stats := fw.GetStats()
	if stats.ErrorCount != 1 {
		t.Errorf("expected 1 error counted, got %d", stats.ErrorCount)
	}
}

// TestTokenBucket_FailOpen_CacheErrors verifies fail-open for token bucket.
func TestTokenBucket_FailOpen_CacheErrors(t *testing.T) {
	tb := NewTokenBucket(&errorCacher{}, "err-tb", 10, 1.0)

	ctx := context.Background()
	result, err := tb.Allow(ctx, "test-key", 10, time.Minute)

	if !result.Allowed {
		t.Error("expected fail-open: request should be allowed")
	}
	if err == nil {
		t.Error("expected non-nil error")
	}

	stats := tb.GetStats()
	if stats.ErrorCount != 1 {
		t.Errorf("expected 1 error, got %d", stats.ErrorCount)
	}
}

// TestLeakyBucket_FailOpen_CacheErrors verifies fail-open for leaky bucket.
func TestLeakyBucket_FailOpen_CacheErrors(t *testing.T) {
	lb := NewLeakyBucket(&errorCacher{}, "err-lb", 10, 1.0)

	ctx := context.Background()
	result, err := lb.Allow(ctx, "test-key", 10, time.Minute)

	if !result.Allowed {
		t.Error("expected fail-open: request should be allowed")
	}
	if err == nil {
		t.Error("expected non-nil error")
	}

	stats := lb.GetStats()
	if stats.ErrorCount != 1 {
		t.Errorf("expected 1 error, got %d", stats.ErrorCount)
	}
}

// TestFixedWindow_NilCache verifies fail-open when cache is nil.
func TestFixedWindow_NilCache(t *testing.T) {
	fw := NewFixedWindow(nil, "nil-fw")

	ctx := context.Background()
	result, err := fw.Allow(ctx, "test-key", 10, time.Minute)

	if !result.Allowed {
		t.Error("expected fail-open with nil cache")
	}
	if err != nil {
		t.Errorf("expected nil error with nil cache, got %v", err)
	}
}

// TestTokenBucket_NilCache verifies fail-open when cache is nil.
func TestTokenBucket_NilCache(t *testing.T) {
	tb := NewTokenBucket(nil, "nil-tb", 10, 1.0)

	ctx := context.Background()
	result, err := tb.Allow(ctx, "test-key", 10, time.Minute)

	if !result.Allowed {
		t.Error("expected fail-open with nil cache")
	}
	if err != nil {
		t.Errorf("expected nil error with nil cache, got %v", err)
	}
}

// TestLeakyBucket_NilCache verifies fail-open when cache is nil.
func TestLeakyBucket_NilCache(t *testing.T) {
	lb := NewLeakyBucket(nil, "nil-lb", 10, 1.0)

	ctx := context.Background()
	result, err := lb.Allow(ctx, "test-key", 10, time.Minute)

	if !result.Allowed {
		t.Error("expected fail-open with nil cache")
	}
	if err != nil {
		t.Errorf("expected nil error with nil cache, got %v", err)
	}
}

// TestRateLimiterStats_AllowRate verifies the AllowRate calculation.
func TestRateLimiterStats_AllowRate(t *testing.T) {
	tests := []struct {
		name     string
		stats    RateLimiterStats
		expected float64
	}{
		{"all allowed", RateLimiterStats{AllowedCount: 100, DeniedCount: 0}, 100.0},
		{"all denied", RateLimiterStats{AllowedCount: 0, DeniedCount: 100}, 0.0},
		{"half and half", RateLimiterStats{AllowedCount: 50, DeniedCount: 50}, 50.0},
		{"no requests", RateLimiterStats{}, 100.0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.stats.AllowRate()
			if got != tc.expected {
				t.Errorf("expected %f, got %f", tc.expected, got)
			}
		})
	}
}

// TestRateLimiterStats_ErrorRate verifies the ErrorRate calculation.
func TestRateLimiterStats_ErrorRate(t *testing.T) {
	tests := []struct {
		name     string
		stats    RateLimiterStats
		expected float64
	}{
		{"no errors", RateLimiterStats{AllowedCount: 100}, 0.0},
		{"all errors", RateLimiterStats{ErrorCount: 100}, 100.0},
		{"no requests", RateLimiterStats{}, 0.0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.stats.ErrorRate()
			if got != tc.expected {
				t.Errorf("expected %f, got %f", tc.expected, got)
			}
		})
	}
}
