package limits

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConcurrencyLimiter_NoLimitConfigured(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	limiter := NewConcurrencyLimiter(cache)
	ctx := context.Background()

	// Provider with no limit configured should always be allowed
	allowed, err := limiter.Acquire(ctx, "unconfigured-provider")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Release should be a no-op for unconfigured provider
	limiter.Release(ctx, "unconfigured-provider")
}

func TestConcurrencyLimiter_ZeroLimit(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	limiter := NewConcurrencyLimiter(cache)
	limiter.Configure("provider-zero", 0)
	ctx := context.Background()

	// Zero limit means no limit, should always allow
	allowed, err := limiter.Acquire(ctx, "provider-zero")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestConcurrencyLimiter_UpToLimit(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	limiter := NewConcurrencyLimiter(cache)
	limiter.Configure("openai", 3)
	ctx := context.Background()

	// Acquire up to the limit - all should succeed
	for i := 0; i < 3; i++ {
		allowed, err := limiter.Acquire(ctx, "openai")
		require.NoError(t, err)
		assert.True(t, allowed, "request %d should be allowed", i+1)
	}
}

func TestConcurrencyLimiter_OverLimit(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	limiter := NewConcurrencyLimiter(cache)
	limiter.Configure("openai", 2)
	ctx := context.Background()

	// Fill up the limit
	allowed, err := limiter.Acquire(ctx, "openai")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = limiter.Acquire(ctx, "openai")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Third request should be rejected
	allowed, err = limiter.Acquire(ctx, "openai")
	require.NoError(t, err)
	assert.False(t, allowed, "third request should be rejected when limit is 2")
}

func TestConcurrencyLimiter_ReleaseDecrementsCounter(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	limiter := NewConcurrencyLimiter(cache)
	limiter.Configure("anthropic", 1)
	ctx := context.Background()

	// Acquire the single slot
	allowed, err := limiter.Acquire(ctx, "anthropic")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Next acquire should fail
	allowed, err = limiter.Acquire(ctx, "anthropic")
	require.NoError(t, err)
	assert.False(t, allowed)

	// Release the slot
	limiter.Release(ctx, "anthropic")

	// Now acquire should succeed again
	allowed, err = limiter.Acquire(ctx, "anthropic")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestConcurrencyLimiter_CacheError_FailsOpen(t *testing.T) {
	// Use a closed cache to simulate errors
	cache := newTestCacher(t)
	cache.Close()

	limiter := NewConcurrencyLimiter(cache)
	limiter.Configure("openai", 1)
	ctx := context.Background()

	// Should fail open (return true) when cache errors
	allowed, err := limiter.Acquire(ctx, "openai")
	require.NoError(t, err)
	assert.True(t, allowed, "should fail open on cache error")
}

func TestConcurrencyLimiter_ConcurrentAccess(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	limiter := NewConcurrencyLimiter(cache)
	limiter.Configure("openai", 5)
	ctx := context.Background()

	const goroutines = 20
	var (
		wg       sync.WaitGroup
		acquired int64
		mu       sync.Mutex
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ok, err := limiter.Acquire(ctx, "openai")
			if err != nil {
				return
			}
			if ok {
				mu.Lock()
				acquired++
				mu.Unlock()
				// Simulate work then release
				limiter.Release(ctx, "openai")
			}
		}()
	}

	wg.Wait()

	// All goroutines should have completed without panics.
	// Due to race conditions, some may have been rejected, but the test
	// should not deadlock or panic. At minimum, at least some should succeed.
	mu.Lock()
	assert.Greater(t, acquired, int64(0), "at least some requests should succeed")
	mu.Unlock()
}

func TestConcurrencyLimiter_MultipleProviders(t *testing.T) {
	cache := newTestCacher(t)
	defer cache.Close()

	limiter := NewConcurrencyLimiter(cache)
	limiter.Configure("openai", 1)
	limiter.Configure("anthropic", 1)
	ctx := context.Background()

	// Fill openai slot
	allowed, err := limiter.Acquire(ctx, "openai")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Anthropic should still have capacity (independent counters)
	allowed, err = limiter.Acquire(ctx, "anthropic")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Both should now be full
	allowed, err = limiter.Acquire(ctx, "openai")
	require.NoError(t, err)
	assert.False(t, allowed)

	allowed, err = limiter.Acquire(ctx, "anthropic")
	require.NoError(t, err)
	assert.False(t, allowed)
}
