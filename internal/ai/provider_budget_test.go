package ai

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newProviderBudgetTestCacher(t *testing.T) cacher.Cacher {
	t.Helper()
	c, err := cacher.NewMemoryCacher(cacher.Settings{})
	require.NoError(t, err)
	return c
}

func TestProviderBudget_WithinBudget(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	budgets := map[string]*ProviderBudgetConfig{
		"openai":    {BudgetUSD: 100, Period: "daily"},
		"anthropic": {BudgetUSD: 200, Period: "daily"},
	}
	router := NewProviderBudgetRouter(cache, budgets)
	ctx := context.Background()

	// Initially all providers are within budget.
	assert.True(t, router.IsWithinBudget(ctx, "openai"))
	assert.True(t, router.IsWithinBudget(ctx, "anthropic"))
}

func TestProviderBudget_ExhaustionShiftsTraffic(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	budgets := map[string]*ProviderBudgetConfig{
		"openai":    {BudgetUSD: 100, Period: "daily"},
		"anthropic": {BudgetUSD: 200, Period: "daily"},
	}
	router := NewProviderBudgetRouter(cache, budgets)
	ctx := context.Background()

	// Exhaust OpenAI's budget.
	err := router.RecordSpend(ctx, "openai", 105.0)
	require.NoError(t, err)

	assert.False(t, router.IsWithinBudget(ctx, "openai"), "openai should be over budget")
	assert.True(t, router.IsWithinBudget(ctx, "anthropic"), "anthropic should still have budget")

	// FilterProviders should exclude openai.
	available := router.FilterProviders(ctx, []string{"openai", "anthropic"})
	assert.Equal(t, []string{"anthropic"}, available)
}

func TestProviderBudget_AllExhaustedFailsOpen(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	budgets := map[string]*ProviderBudgetConfig{
		"openai":    {BudgetUSD: 100, Period: "daily"},
		"anthropic": {BudgetUSD: 200, Period: "daily"},
	}
	router := NewProviderBudgetRouter(cache, budgets)
	ctx := context.Background()

	// Exhaust both providers.
	require.NoError(t, router.RecordSpend(ctx, "openai", 150.0))
	require.NoError(t, router.RecordSpend(ctx, "anthropic", 250.0))

	// FilterProviders should fail open and return all.
	available := router.FilterProviders(ctx, []string{"openai", "anthropic"})
	assert.Equal(t, []string{"openai", "anthropic"}, available)
}

func TestProviderBudget_NoBudgetConfigured(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	budgets := map[string]*ProviderBudgetConfig{
		"openai": {BudgetUSD: 100, Period: "daily"},
	}
	router := NewProviderBudgetRouter(cache, budgets)
	ctx := context.Background()

	// Provider without config is always within budget.
	assert.True(t, router.IsWithinBudget(ctx, "google"))
	assert.Equal(t, -1.0, router.RemainingBudget(ctx, "google"))

	// FilterProviders should include unconfigured providers.
	available := router.FilterProviders(ctx, []string{"openai", "google"})
	assert.Contains(t, available, "google")
	assert.Contains(t, available, "openai")
}

func TestProviderBudget_RecordAndGetSpend(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	budgets := map[string]*ProviderBudgetConfig{
		"openai": {BudgetUSD: 100, Period: "daily"},
	}
	router := NewProviderBudgetRouter(cache, budgets)
	ctx := context.Background()

	// Record multiple spends.
	require.NoError(t, router.RecordSpend(ctx, "openai", 25.5))
	require.NoError(t, router.RecordSpend(ctx, "openai", 10.0))

	spend, err := router.GetSpend(ctx, "openai")
	require.NoError(t, err)
	assert.InDelta(t, 35.5, spend, 0.01, "spend should accumulate")
}

func TestProviderBudget_RemainingBudget(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	budgets := map[string]*ProviderBudgetConfig{
		"openai": {BudgetUSD: 100, Period: "daily"},
	}
	router := NewProviderBudgetRouter(cache, budgets)
	ctx := context.Background()

	remaining := router.RemainingBudget(ctx, "openai")
	assert.Equal(t, 100.0, remaining, "full budget should remain initially")

	require.NoError(t, router.RecordSpend(ctx, "openai", 40.0))
	remaining = router.RemainingBudget(ctx, "openai")
	assert.InDelta(t, 60.0, remaining, 0.01)

	// Over-spend should clamp to 0.
	require.NoError(t, router.RecordSpend(ctx, "openai", 80.0))
	remaining = router.RemainingBudget(ctx, "openai")
	assert.Equal(t, 0.0, remaining)
}

func TestProviderBudget_ZeroCostNotRecorded(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	budgets := map[string]*ProviderBudgetConfig{
		"openai": {BudgetUSD: 100, Period: "daily"},
	}
	router := NewProviderBudgetRouter(cache, budgets)
	ctx := context.Background()

	// Recording zero cost should be a no-op.
	require.NoError(t, router.RecordSpend(ctx, "openai", 0))
	require.NoError(t, router.RecordSpend(ctx, "openai", -5.0))

	spend, err := router.GetSpend(ctx, "openai")
	require.NoError(t, err)
	assert.Equal(t, 0.0, spend, "no spend should be recorded for zero/negative amounts")
}

func TestProviderBudget_MonthlyPeriod(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	budgets := map[string]*ProviderBudgetConfig{
		"anthropic": {BudgetUSD: 500, Period: "monthly"},
	}
	router := NewProviderBudgetRouter(cache, budgets)
	ctx := context.Background()

	require.NoError(t, router.RecordSpend(ctx, "anthropic", 400.0))
	assert.True(t, router.IsWithinBudget(ctx, "anthropic"))

	require.NoError(t, router.RecordSpend(ctx, "anthropic", 150.0))
	assert.False(t, router.IsWithinBudget(ctx, "anthropic"))
}

func TestProviderBudget_DistributedTracking(t *testing.T) {
	// Simulate two "instances" sharing the same cache.
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	budgets := map[string]*ProviderBudgetConfig{
		"openai": {BudgetUSD: 100, Period: "daily"},
	}
	router1 := NewProviderBudgetRouter(cache, budgets)
	router2 := NewProviderBudgetRouter(cache, budgets)
	ctx := context.Background()

	// Instance 1 records spend.
	require.NoError(t, router1.RecordSpend(ctx, "openai", 60.0))
	// Instance 2 records spend.
	require.NoError(t, router2.RecordSpend(ctx, "openai", 50.0))

	// Both instances should see the combined spend.
	spend1, err := router1.GetSpend(ctx, "openai")
	require.NoError(t, err)
	assert.InDelta(t, 110.0, spend1, 0.01)

	spend2, err := router2.GetSpend(ctx, "openai")
	require.NoError(t, err)
	assert.InDelta(t, 110.0, spend2, 0.01)

	// Both should see it as over budget.
	assert.False(t, router1.IsWithinBudget(ctx, "openai"))
	assert.False(t, router2.IsWithinBudget(ctx, "openai"))
}

func TestProviderBudget_EmptyBudgetMap(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	router := NewProviderBudgetRouter(cache, nil)
	ctx := context.Background()

	// Everything should pass through when no budgets are configured.
	assert.True(t, router.IsWithinBudget(ctx, "openai"))
	available := router.FilterProviders(ctx, []string{"openai", "anthropic"})
	assert.Equal(t, []string{"openai", "anthropic"}, available)
}

func TestProviderBudget_PeriodTTL(t *testing.T) {
	// Sanity check that periodTTL returns positive durations.
	dailyTTL := periodTTL("daily")
	assert.True(t, dailyTTL > 0, "daily TTL should be positive")
	assert.True(t, dailyTTL <= 24*60*60*1e9, "daily TTL should not exceed 24 hours")

	monthlyTTL := periodTTL("monthly")
	assert.True(t, monthlyTTL > 0, "monthly TTL should be positive")
	assert.True(t, monthlyTTL <= 31*24*60*60*1e9, "monthly TTL should not exceed 31 days")
}

func TestProviderBudget_FilterProviders_NoBudgetsConfigured(t *testing.T) {
	cache := newProviderBudgetTestCacher(t)
	defer cache.Close()

	router := NewProviderBudgetRouter(cache, map[string]*ProviderBudgetConfig{})
	ctx := context.Background()

	providers := []string{"openai", "anthropic", "google"}
	available := router.FilterProviders(ctx, providers)
	assert.Equal(t, providers, available, "empty budget map should pass all through")
}
