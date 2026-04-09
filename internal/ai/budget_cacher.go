// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"io"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

const budgetCacheType = "ai_budget"

// CacherBudgetStore implements BudgetStore using cacher.Cacher (Redis, Pebble, or Memory).
// Cost is stored as microdollars (int64) since cacher increment only works with integers.
type CacherBudgetStore struct {
	cache cacher.Cacher
}

// NewCacherBudgetStore creates a new cacher-backed budget store.
func NewCacherBudgetStore(cache cacher.Cacher) *CacherBudgetStore {
	return &CacherBudgetStore{cache: cache}
}

// GetUsage returns the usage for the CacherBudgetStore.
func (s *CacherBudgetStore) GetUsage(ctx context.Context, key string, period string) (*BudgetUsage, error) {
	ttl := PeriodTTL(period)

	// IncrementWithExpires with 0 returns the current value without incrementing
	tokens, err := s.cache.IncrementWithExpires(ctx, budgetCacheType, key+":"+period+":tokens", 0, ttl)
	if err != nil {
		return nil, err
	}

	costMicro, err := s.cache.IncrementWithExpires(ctx, budgetCacheType, key+":"+period+":cost", 0, ttl)
	if err != nil {
		return nil, err
	}

	return &BudgetUsage{
		Tokens:  tokens,
		CostUSD: float64(costMicro) / 1_000_000,
	}, nil
}

// GetUsageReadOnly returns current usage without refreshing TTL
func (s *CacherBudgetStore) GetUsageReadOnly(ctx context.Context, key string, period string) (*BudgetUsage, error) {
	// Use Get to read without touching TTL (Get does not refresh expiry)
	tokensReader, err := s.cache.Get(ctx, budgetCacheType, key+":"+period+":tokens")
	if err != nil {
		return nil, err
	}

	costReader, err := s.cache.Get(ctx, budgetCacheType, key+":"+period+":cost")
	if err != nil {
		return nil, err
	}

	// Parse tokens from reader
	tokensBytes, err := io.ReadAll(tokensReader)
	if err != nil {
		return nil, err
	}

	// Parse cost from reader
	costBytes, err := io.ReadAll(costReader)
	if err != nil {
		return nil, err
	}

	var tokens, costMicro int64
	if len(tokensBytes) > 0 {
		_, _ = fmt.Sscanf(string(tokensBytes), "%d", &tokens)
	}
	if len(costBytes) > 0 {
		_, _ = fmt.Sscanf(string(costBytes), "%d", &costMicro)
	}

	return &BudgetUsage{
		Tokens:  tokens,
		CostUSD: float64(costMicro) / 1_000_000,
	}, nil
}

// IncrUsage performs the incr usage operation on the CacherBudgetStore.
func (s *CacherBudgetStore) IncrUsage(ctx context.Context, key string, period string, tokens int64, costUSD float64) error {
	ttl := PeriodTTL(period)

	if tokens > 0 {
		if _, err := s.cache.IncrementWithExpires(ctx, budgetCacheType, key+":"+period+":tokens", tokens, ttl); err != nil {
			return err
		}
	}

	if costUSD > 0 {
		costMicro := int64(costUSD * 1_000_000)
		if _, err := s.cache.IncrementWithExpires(ctx, budgetCacheType, key+":"+period+":cost", costMicro, ttl); err != nil {
			return err
		}
	}

	return nil
}
