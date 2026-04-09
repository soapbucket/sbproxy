// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// ProviderBudgetConfig defines a spend cap for a single provider within a time period.
type ProviderBudgetConfig struct {
	BudgetUSD float64 `json:"budget_usd"`
	Period    string  `json:"period"` // "daily" or "monthly"
}

// ProviderBudgetRouter tracks per-provider spend using distributed counters
// and filters out providers whose budget is exhausted.
type ProviderBudgetRouter struct {
	cache   cacher.Cacher
	prefix  string
	budgets map[string]*ProviderBudgetConfig
}

// NewProviderBudgetRouter creates a router backed by the given cache.
// The budgets map is keyed by provider name (e.g., "openai", "anthropic").
func NewProviderBudgetRouter(cache cacher.Cacher, budgets map[string]*ProviderBudgetConfig) *ProviderBudgetRouter {
	return &ProviderBudgetRouter{
		cache:   cache,
		prefix:  "ai:provider_budget",
		budgets: budgets,
	}
}

// periodKey returns the cache key for a provider's spend counter in the current period.
// Format: "ai:provider_budget:<provider>:<period>:<date>"
func (r *ProviderBudgetRouter) periodKey(provider string, period string) string {
	now := time.Now().UTC()
	var datePart string
	switch period {
	case "monthly":
		datePart = fmt.Sprintf("monthly:%d-%02d", now.Year(), now.Month())
	default: // "daily" is the default
		datePart = fmt.Sprintf("daily:%s", now.Format("2006-01-02"))
	}
	return fmt.Sprintf("%s:%s:%s", r.prefix, provider, datePart)
}

// periodTTL returns the TTL for the current period's counter.
// It returns the remaining time until the period boundary so counters auto-expire.
func periodTTL(period string) time.Duration {
	now := time.Now().UTC()
	switch period {
	case "monthly":
		// Time until the first day of next month.
		year, month, _ := now.Date()
		nextMonth := time.Date(year, month+1, 1, 0, 0, 0, 0, time.UTC)
		remaining := nextMonth.Sub(now)
		if remaining <= 0 {
			return 31 * 24 * time.Hour
		}
		return remaining
	default: // "daily"
		// Time until midnight UTC.
		tomorrow := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
		remaining := tomorrow.Sub(now)
		if remaining <= 0 {
			return 24 * time.Hour
		}
		return remaining
	}
}

// GetSpend returns the current spend in USD for a provider in the current period.
func (r *ProviderBudgetRouter) GetSpend(ctx context.Context, provider string) (float64, error) {
	cfg, ok := r.budgets[provider]
	if !ok {
		return 0, nil
	}
	key := r.periodKey(provider, cfg.Period)
	ttl := periodTTL(cfg.Period)
	// IncrementWithExpires with 0 reads the current value without incrementing.
	costMicro, err := r.cache.IncrementWithExpires(ctx, "ai_provider_budget", key, 0, ttl)
	if err != nil {
		return 0, err
	}
	return float64(costMicro) / 1_000_000, nil
}

// RecordSpend atomically adds the given cost to the provider's period counter.
func (r *ProviderBudgetRouter) RecordSpend(ctx context.Context, provider string, costUSD float64) error {
	cfg, ok := r.budgets[provider]
	if !ok {
		return nil // no budget configured for this provider
	}
	if costUSD <= 0 {
		return nil
	}
	key := r.periodKey(provider, cfg.Period)
	ttl := periodTTL(cfg.Period)
	costMicro := int64(costUSD * 1_000_000)
	_, err := r.cache.IncrementWithExpires(ctx, "ai_provider_budget", key, costMicro, ttl)
	return err
}

// IsWithinBudget returns true if the provider has not exhausted its budget.
// Providers without a configured budget are always within budget.
func (r *ProviderBudgetRouter) IsWithinBudget(ctx context.Context, provider string) bool {
	cfg, ok := r.budgets[provider]
	if !ok {
		return true // no limit configured
	}
	spend, err := r.GetSpend(ctx, provider)
	if err != nil {
		slog.Warn("provider budget check failed, allowing provider",
			"provider", provider,
			"error", err,
		)
		return true // fail open
	}
	return spend < cfg.BudgetUSD
}

// FilterProviders returns a subset of the given provider names that are still
// within their budget. If all providers are exhausted, the full list is returned
// so the caller can still route (fail open).
func (r *ProviderBudgetRouter) FilterProviders(ctx context.Context, providers []string) []string {
	if len(r.budgets) == 0 {
		return providers
	}

	available := make([]string, 0, len(providers))
	for _, p := range providers {
		if r.IsWithinBudget(ctx, p) {
			available = append(available, p)
		}
	}

	// Fail open: if every provider is over budget, return them all.
	if len(available) == 0 {
		slog.Warn("all providers over budget, failing open",
			"providers", providers,
		)
		return providers
	}
	return available
}

// RemainingBudget returns how much USD remains for the provider in the current period.
// Returns -1 if the provider has no budget configured (unlimited).
func (r *ProviderBudgetRouter) RemainingBudget(ctx context.Context, provider string) float64 {
	cfg, ok := r.budgets[provider]
	if !ok {
		return -1
	}
	spend, err := r.GetSpend(ctx, provider)
	if err != nil {
		return cfg.BudgetUSD // assume no spend on error
	}
	remaining := cfg.BudgetUSD - spend
	if remaining < 0 {
		return 0
	}
	return remaining
}
