package ai

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBudgetEnforcer_Block(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{{
			Scope:     "workspace",
			MaxTokens: 1000,
			Period:    "daily",
		}},
		OnExceed: "block",
	}, store)

	ctx := context.Background()

	// Record some usage
	require.NoError(t, be.Record(ctx, "ws-1", 900, 0))

	// Should still be within budget
	assert.NoError(t, be.Check(ctx, "ws-1", 50))

	// Should exceed budget
	err := be.Check(ctx, "ws-1", 200)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "budget_exceeded")
}

func TestBudgetEnforcer_CostLimit(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{{
			Scope:      "api_key",
			MaxCostUSD: 10.00,
			Period:     "monthly",
		}},
		OnExceed: "block",
	}, store)

	ctx := context.Background()

	// Record cost
	require.NoError(t, be.Record(ctx, "key-1", 5000, 10.01))

	// Should exceed cost limit
	err := be.Check(ctx, "key-1", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cost budget exceeded")
}

func TestBudgetEnforcer_LogMode(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{{
			Scope:     "user",
			MaxTokens: 100,
			Period:    "hourly",
		}},
		OnExceed: "log", // log mode doesn't block
	}, store)

	ctx := context.Background()
	require.NoError(t, be.Record(ctx, "user-1", 200, 0))

	// Should not error in log mode
	assert.NoError(t, be.Check(ctx, "user-1", 100))
}

func TestBudgetEnforcer_MultipleLimits(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{
			{Scope: "workspace", MaxTokens: 10000, Period: "daily"},
			{Scope: "api_key", MaxTokens: 5000, Period: "hourly"},
		},
		OnExceed: "block",
	}, store)

	ctx := context.Background()

	// Record usage that exceeds hourly but not daily
	require.NoError(t, be.Record(ctx, "key-1", 4900, 0))

	// Should exceed hourly limit
	err := be.Check(ctx, "key-1", 200)
	assert.Error(t, err)
}

func TestBudgetEnforcer_NoUsage(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{{
			Scope:     "workspace",
			MaxTokens: 1000,
			Period:    "daily",
		}},
	}, store)

	// No usage recorded — should be fine
	assert.NoError(t, be.Check(context.Background(), "ws-1", 100))
}

func TestBudgetEnforcer_Record(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{{
			Scope:     "workspace",
			MaxTokens: 10000,
			Period:    "daily",
		}},
	}, store)

	ctx := context.Background()
	require.NoError(t, be.Record(ctx, "ws-1", 100, 0.05))
	require.NoError(t, be.Record(ctx, "ws-1", 200, 0.10))

	usage, err := store.GetUsage(ctx, "budget:workspace:ws-1", "daily")
	require.NoError(t, err)
	assert.Equal(t, int64(300), usage.Tokens)
	assert.InDelta(t, 0.15, usage.CostUSD, 0.001)
}

func TestPeriodTTL(t *testing.T) {
	assert.Greater(t, PeriodTTL("hourly").Seconds(), float64(3500))
	assert.Greater(t, PeriodTTL("daily").Hours(), float64(23))
	assert.Greater(t, PeriodTTL("weekly").Hours(), float64(167))
	assert.Greater(t, PeriodTTL("monthly").Hours(), float64(719))
	assert.Greater(t, PeriodTTL("unknown").Hours(), float64(23)) // defaults to daily
}

func TestBudgetEnforcer_TagScope(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{
			{Scope: "workspace", MaxTokens: 100000, Period: "daily"},
			{Scope: "tag:team", MaxTokens: 5000, Period: "daily"},
		},
		OnExceed: "block",
	}, store)

	ctx := context.Background()
	tags := map[string]string{"team": "platform"}

	// Record usage for the team tag
	require.NoError(t, be.RecordTagBudgets(ctx, tags, 4500, 0))

	// Should still be within tag budget
	assert.NoError(t, be.CheckTagBudgets(ctx, tags, 400))

	// Should exceed tag budget
	err := be.CheckTagBudgets(ctx, tags, 600)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tag:team=platform")
}

func TestBudgetLimit_IsTagScope(t *testing.T) {
	assert.True(t, BudgetLimit{Scope: "tag:team"}.IsTagScope())
	assert.True(t, BudgetLimit{Scope: "tag:department"}.IsTagScope())
	assert.False(t, BudgetLimit{Scope: "workspace"}.IsTagScope())
	assert.False(t, BudgetLimit{Scope: "api_key"}.IsTagScope())
}

func TestBudgetLimit_TagKey(t *testing.T) {
	assert.Equal(t, "team", BudgetLimit{Scope: "tag:team"}.TagKey())
	assert.Equal(t, "department", BudgetLimit{Scope: "tag:department"}.TagKey())
	assert.Equal(t, "", BudgetLimit{Scope: "workspace"}.TagKey())
}

func TestBudgetEnforcer_TagScope_MissingTag(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{
			{Scope: "tag:team", MaxTokens: 1000, Period: "daily"},
		},
		OnExceed: "block",
	}, store)

	ctx := context.Background()
	// Empty tags - should pass (no matching tag to enforce)
	assert.NoError(t, be.CheckTagBudgets(ctx, map[string]string{}, 500))
	// Missing team tag - should pass
	assert.NoError(t, be.CheckTagBudgets(ctx, map[string]string{"project": "alpha"}, 500))
}

func TestBudgetEnforcer_TagScope_CostLimit(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{
			{Scope: "tag:team", MaxCostUSD: 10.00, Period: "monthly"},
		},
		OnExceed: "block",
	}, store)

	ctx := context.Background()
	tags := map[string]string{"team": "ml-ops"}

	require.NoError(t, be.RecordTagBudgets(ctx, tags, 0, 10.01))
	err := be.CheckTagBudgets(ctx, tags, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cost budget exceeded")
}

func TestInMemoryBudgetStore(t *testing.T) {
	store := NewInMemoryBudgetStore()
	ctx := context.Background()

	// Initially empty
	usage, err := store.GetUsage(ctx, "test-key", "daily")
	require.NoError(t, err)
	assert.Equal(t, int64(0), usage.Tokens)

	// Increment
	require.NoError(t, store.IncrUsage(ctx, "test-key", "daily", 100, 0.05))
	require.NoError(t, store.IncrUsage(ctx, "test-key", "daily", 50, 0.025))

	usage, err = store.GetUsage(ctx, "test-key", "daily")
	require.NoError(t, err)
	assert.Equal(t, int64(150), usage.Tokens)
	assert.InDelta(t, 0.075, usage.CostUSD, 0.001)
}

func TestBudgetEnforcer_CheckScopesAndRecordScopes(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{
			{Scope: "workspace", MaxTokens: 10000, Period: "daily"},
			{Scope: "api_key", MaxTokens: 1000, Period: "daily"},
			{Scope: "tag:team", MaxTokens: 500, Period: "daily"},
		},
		OnExceed: "block",
	}, store)

	ctx := context.Background()
	scopeValues := map[string]string{
		"workspace": "ws-1",
		"api_key":   "key-1",
		"tag:team":  "platform",
	}

	require.NoError(t, be.RecordScopes(ctx, scopeValues, 450, 0))

	workspaceUsage, err := store.GetUsage(ctx, "budget:workspace:ws-1", "daily")
	require.NoError(t, err)
	assert.Equal(t, int64(450), workspaceUsage.Tokens)

	apiKeyUsage, err := store.GetUsage(ctx, "budget:api_key:key-1", "daily")
	require.NoError(t, err)
	assert.Equal(t, int64(450), apiKeyUsage.Tokens)

	tagUsage, err := store.GetUsage(ctx, "budget:tag:team:platform", "daily")
	require.NoError(t, err)
	assert.Equal(t, int64(450), tagUsage.Tokens)

	decision, err := be.CheckScopes(ctx, scopeValues, 100)
	assert.Error(t, err)
	require.NotNil(t, decision)
	assert.Equal(t, "tag:team", decision.Limit.Scope)
	assert.Equal(t, "platform", decision.ScopeValue)
}

func TestBudgetEnforcer_CheckScopes_PicksMostSpecificExceededScope(t *testing.T) {
	store := NewInMemoryBudgetStore()
	be := NewBudgetEnforcer(&BudgetConfig{
		Limits: []BudgetLimit{
			{Scope: "workspace", MaxTokens: 1000, Period: "daily"},
			{Scope: "api_key", MaxTokens: 500, Period: "daily"},
		},
		OnExceed: "block",
	}, store)

	ctx := context.Background()
	scopeValues := map[string]string{
		"workspace": "ws-1",
		"api_key":   "key-1",
	}
	require.NoError(t, be.RecordScopes(ctx, scopeValues, 900, 0))

	decision, err := be.CheckScopes(ctx, scopeValues, 50)
	require.Error(t, err)
	require.NotNil(t, decision)
	assert.Equal(t, "api_key", decision.Limit.Scope)
	assert.Equal(t, "key-1", decision.ScopeValue)
}
