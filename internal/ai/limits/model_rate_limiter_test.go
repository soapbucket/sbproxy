package limits

import (
	"context"
	"sync"
	"testing"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newModelRateLimiterTestCacher(t *testing.T) cacher.Cacher {
	t.Helper()
	c, err := cacher.NewMemoryCacher(cacher.Settings{})
	require.NoError(t, err)
	return c
}

func TestModelRateLimiter_NoConfig(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	ctx := context.Background()

	// No configuration for this model, should always be allowed.
	res, err := rl.AllowRequest(ctx, "openai", "gpt-4")
	require.NoError(t, err)
	assert.True(t, res.Allowed)

	res, err = rl.AllowTokens(ctx, "openai", "gpt-4", 100000)
	require.NoError(t, err)
	assert.True(t, res.Allowed)
}

func TestModelRateLimiter_RPMLimit(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	rl.Configure("openai", "gpt-4", ModelRateConfig{RPM: 5})
	ctx := context.Background()

	// First 5 requests should be allowed.
	for i := 0; i < 5; i++ {
		res, err := rl.AllowRequest(ctx, "openai", "gpt-4")
		require.NoError(t, err)
		assert.True(t, res.Allowed, "request %d should be allowed", i+1)
	}

	// 6th request should be denied.
	res, err := rl.AllowRequest(ctx, "openai", "gpt-4")
	require.NoError(t, err)
	assert.False(t, res.Allowed, "request 6 should be denied")
	assert.Equal(t, 0, res.Remaining)
	assert.False(t, res.ResetTime.IsZero(), "ResetTime should be set")
}

func TestModelRateLimiter_TPMLimit(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	rl.Configure("anthropic", "claude-3", ModelRateConfig{TPM: 1000})
	ctx := context.Background()

	// Use 800 tokens, should be allowed.
	res, err := rl.AllowTokens(ctx, "anthropic", "claude-3", 800)
	require.NoError(t, err)
	assert.True(t, res.Allowed)

	// Try to use 300 more tokens (total 1100 > 1000), should be denied.
	res, err = rl.AllowTokens(ctx, "anthropic", "claude-3", 300)
	require.NoError(t, err)
	assert.False(t, res.Allowed, "tokens exceeding limit should be denied")
	assert.Equal(t, 0, res.Remaining)
}

func TestModelRateLimiter_ZeroRPM(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	// RPM is 0, so RPM check should be bypassed. TPM is set.
	rl.Configure("openai", "gpt-4", ModelRateConfig{RPM: 0, TPM: 500})
	ctx := context.Background()

	// RPM check should pass (no limit).
	res, err := rl.AllowRequest(ctx, "openai", "gpt-4")
	require.NoError(t, err)
	assert.True(t, res.Allowed)

	// TPM check should enforce limits.
	res, err = rl.AllowTokens(ctx, "openai", "gpt-4", 600)
	require.NoError(t, err)
	assert.False(t, res.Allowed)
}

func TestModelRateLimiter_RemainingAndResetTime(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	rl.Configure("openai", "gpt-4", ModelRateConfig{RPM: 10})
	ctx := context.Background()

	// Use 3 requests.
	for i := 0; i < 3; i++ {
		_, err := rl.AllowRequest(ctx, "openai", "gpt-4")
		require.NoError(t, err)
	}

	// 4th request should show remaining capacity.
	res, err := rl.AllowRequest(ctx, "openai", "gpt-4")
	require.NoError(t, err)
	assert.True(t, res.Allowed)
	assert.True(t, res.Remaining > 0, "should have remaining capacity")
	assert.False(t, res.ResetTime.IsZero(), "ResetTime should be set")
}

func TestModelRateLimiter_IsolationBetweenModels(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	rl.Configure("openai", "gpt-4", ModelRateConfig{RPM: 2})
	rl.Configure("openai", "gpt-3.5", ModelRateConfig{RPM: 2})
	ctx := context.Background()

	// Exhaust gpt-4 limit.
	for i := 0; i < 2; i++ {
		res, err := rl.AllowRequest(ctx, "openai", "gpt-4")
		require.NoError(t, err)
		assert.True(t, res.Allowed)
	}
	res, err := rl.AllowRequest(ctx, "openai", "gpt-4")
	require.NoError(t, err)
	assert.False(t, res.Allowed, "gpt-4 should be exhausted")

	// gpt-3.5 should still work.
	res, err = rl.AllowRequest(ctx, "openai", "gpt-3.5")
	require.NoError(t, err)
	assert.True(t, res.Allowed, "gpt-3.5 should be independent")
}

func TestModelRateLimiter_FlagOverridesConfigRPM(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	rl.Configure("openai", "gpt-4", ModelRateConfig{RPM: 100})
	ctx := context.Background()

	// Flag overrides RPM to 500.
	flags := map[string]interface{}{
		"ai.models.gpt-4.rpm_limit": float64(500),
	}

	// Send 101 requests; all should be allowed since flag sets limit to 500.
	for i := 0; i < 101; i++ {
		res, err := rl.AllowRequestWithFlags(ctx, "openai", "gpt-4", flags)
		require.NoError(t, err)
		assert.True(t, res.Allowed, "request %d should be allowed with flag override", i+1)
	}
}

func TestModelRateLimiter_FlagNotSet_UsesConfig(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	rl.Configure("openai", "gpt-4", ModelRateConfig{RPM: 5})
	ctx := context.Background()

	// No flag set, uses config RPM of 5.
	for i := 0; i < 5; i++ {
		res, err := rl.AllowRequestWithFlags(ctx, "openai", "gpt-4", nil)
		require.NoError(t, err)
		assert.True(t, res.Allowed, "request %d should be allowed", i+1)
	}

	// 6th request should be denied.
	res, err := rl.AllowRequestWithFlags(ctx, "openai", "gpt-4", nil)
	require.NoError(t, err)
	assert.False(t, res.Allowed, "request 6 should be denied without flag override")
}

func TestModelRateLimiter_FlagZero_UsesConfig(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	rl.Configure("openai", "gpt-4", ModelRateConfig{RPM: 5})
	ctx := context.Background()

	// Flag set to 0 should be treated as no override.
	flags := map[string]interface{}{
		"ai.models.gpt-4.rpm_limit": float64(0),
	}

	for i := 0; i < 5; i++ {
		res, err := rl.AllowRequestWithFlags(ctx, "openai", "gpt-4", flags)
		require.NoError(t, err)
		assert.True(t, res.Allowed, "request %d should be allowed", i+1)
	}

	// 6th request should be denied (config RPM of 5 still applies).
	res, err := rl.AllowRequestWithFlags(ctx, "openai", "gpt-4", flags)
	require.NoError(t, err)
	assert.False(t, res.Allowed, "request 6 should be denied when flag is 0")
}

func TestModelRateLimiter_ConcurrentAccess(t *testing.T) {
	cache := newModelRateLimiterTestCacher(t)
	defer cache.Close()

	rl := NewModelRateLimiter(cache)
	rl.Configure("openai", "gpt-4", ModelRateConfig{RPM: 100, TPM: 10000})
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = rl.AllowRequest(ctx, "openai", "gpt-4")
			_, _ = rl.AllowTokens(ctx, "openai", "gpt-4", 50)
		}()
	}
	wg.Wait()
}
