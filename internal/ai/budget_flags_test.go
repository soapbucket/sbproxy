package ai

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBudgetFlags_EffectiveBudget_NoFlags(t *testing.T) {
	result := effectiveBudget(nil, "workspace", 100.0)
	assert.Equal(t, 100.0, result, "nil flags should return base budget")
}

func TestBudgetFlags_EffectiveBudget_NoMatchingKey(t *testing.T) {
	flags := map[string]any{
		"ai.budget.override_user": 50.0,
	}
	result := effectiveBudget(flags, "workspace", 100.0)
	assert.Equal(t, 100.0, result, "non-matching key should return base budget")
}

func TestBudgetFlags_EffectiveBudget_Override(t *testing.T) {
	flags := map[string]any{
		"ai.budget.override_workspace": 50.0,
	}
	result := effectiveBudget(flags, "workspace", 100.0)
	assert.Equal(t, 150.0, result, "override should add to base budget")
}

func TestBudgetFlags_EffectiveBudget_ZeroOverrideIgnored(t *testing.T) {
	flags := map[string]any{
		"ai.budget.override_workspace": 0.0,
	}
	result := effectiveBudget(flags, "workspace", 100.0)
	assert.Equal(t, 100.0, result, "zero override should be ignored")
}

func TestBudgetFlags_EffectiveBudget_NegativeOverrideIgnored(t *testing.T) {
	flags := map[string]any{
		"ai.budget.override_workspace": -20.0,
	}
	result := effectiveBudget(flags, "workspace", 100.0)
	assert.Equal(t, 100.0, result, "negative override should be ignored")
}

func TestBudgetFlags_EffectiveBudget_NonFloat64Ignored(t *testing.T) {
	flags := map[string]any{
		"ai.budget.override_workspace": "fifty",
	}
	result := effectiveBudget(flags, "workspace", 100.0)
	assert.Equal(t, 100.0, result, "non-float64 override should be ignored")
}

func TestBudgetFlags_PerKeyScoping(t *testing.T) {
	flags := map[string]any{
		"ai.budget.override_workspace": 50.0,
		"ai.budget.override_user":      25.0,
		"ai.budget.override_model":     10.0,
	}

	assert.Equal(t, 150.0, effectiveBudget(flags, "workspace", 100.0))
	assert.Equal(t, 75.0, effectiveBudget(flags, "user", 50.0))
	assert.Equal(t, 30.0, effectiveBudget(flags, "model", 20.0))
	// api_key has no override, should return base
	assert.Equal(t, 80.0, effectiveBudget(flags, "api_key", 80.0))
}

func TestBudgetFlags_ApplyOverrides_NilConfig(t *testing.T) {
	flags := map[string]any{"ai.budget.override_workspace": 50.0}
	result := applyBudgetFlagOverrides(nil, flags)
	assert.Nil(t, result)
}

func TestBudgetFlags_ApplyOverrides_NoFlags(t *testing.T) {
	cfg := &BudgetConfig{
		Limits: []BudgetLimit{
			{Scope: "workspace", MaxCostUSD: 100, Period: "daily"},
		},
	}
	result := applyBudgetFlagOverrides(cfg, nil)
	assert.Same(t, cfg, result, "nil flags should return same config pointer")
}

func TestBudgetFlags_ApplyOverrides_AdjustsCostLimit(t *testing.T) {
	cfg := &BudgetConfig{
		Limits: []BudgetLimit{
			{Scope: "workspace", MaxCostUSD: 100, Period: "daily"},
			{Scope: "user", MaxCostUSD: 20, Period: "daily"},
		},
	}
	flags := map[string]any{
		"ai.budget.override_workspace": 50.0,
	}

	result := applyBudgetFlagOverrides(cfg, flags)
	require.NotNil(t, result)
	assert.NotSame(t, cfg, result, "should return a new config")
	assert.Equal(t, 150.0, result.Limits[0].MaxCostUSD, "workspace limit should be adjusted")
	assert.Equal(t, 20.0, result.Limits[1].MaxCostUSD, "user limit should be unchanged")

	// Original config should be untouched.
	assert.Equal(t, 100.0, cfg.Limits[0].MaxCostUSD, "original config must not be mutated")
}

func TestBudgetFlags_ApplyOverrides_NoMatchReturnsOriginal(t *testing.T) {
	cfg := &BudgetConfig{
		Limits: []BudgetLimit{
			{Scope: "workspace", MaxCostUSD: 100, Period: "daily"},
		},
	}
	flags := map[string]any{
		"ai.budget.override_model": 50.0,
	}

	result := applyBudgetFlagOverrides(cfg, flags)
	assert.Same(t, cfg, result, "no matching override should return same config pointer")
}

func TestBudgetFlags_IntegrationWithBudgetEnforcer(t *testing.T) {
	store := NewInMemoryBudgetStore()
	ctx := context.Background()

	// Seed usage close to the base limit.
	_ = store.IncrUsage(ctx, "budget:workspace:ws-1", "daily", 0, 90.0)

	// Without override, this should exceed the budget.
	baseCfg := &BudgetConfig{
		OnExceed: "block",
		Limits: []BudgetLimit{
			{Scope: "workspace", MaxCostUSD: 100, Period: "daily"},
		},
	}

	enforcer := NewBudgetEnforcer(baseCfg, store)
	scopeValues := map[string]string{"workspace": "ws-1"}
	_, err := enforcer.CheckScopes(ctx, scopeValues, 0)
	assert.NoError(t, err, "90 < 100, should not be exceeded yet")

	// Add more usage to exceed.
	_ = store.IncrUsage(ctx, "budget:workspace:ws-1", "daily", 0, 15.0)
	_, err = enforcer.CheckScopes(ctx, scopeValues, 0)
	assert.Error(t, err, "105 > 100, should be exceeded")

	// Apply flag override that increases budget by 50.
	flags := map[string]any{"ai.budget.override_workspace": 50.0}
	adjustedCfg := applyBudgetFlagOverrides(baseCfg, flags)
	enforcerWithOverride := NewBudgetEnforcer(adjustedCfg, store)
	_, err = enforcerWithOverride.CheckScopes(ctx, scopeValues, 0)
	assert.NoError(t, err, "105 < 150, should pass with override")
}

func TestBudgetFlags_FlagDeletedRestoresBaseBudget(t *testing.T) {
	// First call with override.
	flags := map[string]any{"ai.budget.override_workspace": 50.0}
	result := effectiveBudget(flags, "workspace", 100.0)
	assert.Equal(t, 150.0, result)

	// Flag removed (empty map).
	result = effectiveBudget(map[string]any{}, "workspace", 100.0)
	assert.Equal(t, 100.0, result, "removing flag should restore base budget")
}

func TestBudgetFlags_GetWorkspaceFlags(t *testing.T) {
	// Nil request data.
	assert.Nil(t, getWorkspaceFlags(nil))

	// Request data without flags.
	rd := &reqctx.RequestData{}
	assert.Nil(t, getWorkspaceFlags(rd))

	// Request data with flags.
	rd.FeatureFlags = map[string]any{"ai.budget.override_workspace": 50.0}
	flags := getWorkspaceFlags(rd)
	assert.NotNil(t, flags)
	assert.Equal(t, 50.0, flags["ai.budget.override_workspace"])
}
