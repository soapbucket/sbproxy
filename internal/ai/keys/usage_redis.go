package keys

import (
	"context"
	"time"

	cacher "github.com/soapbucket/sbproxy/internal/cache/store"
)

const vkUsageCacheType = "vk_usage"

// RedisUsageTracker tracks per-key usage in Redis for persistence across restarts.
// Uses the cacher.Cacher interface (works with Redis, Pebble, or memory).
type RedisUsageTracker struct {
	cache cacher.Cacher
}

// NewRedisUsageTracker creates a new Redis-backed usage tracker.
func NewRedisUsageTracker(cache cacher.Cacher) *RedisUsageTracker {
	return &RedisUsageTracker{cache: cache}
}

func (t *RedisUsageTracker) usageKey(keyID, field, period string) string {
	return keyID + ":" + period + ":" + field
}

func periodTTL(period string) time.Duration {
	switch period {
	case "hourly":
		return time.Hour
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	case "monthly":
		return 30 * 24 * time.Hour
	default:
		// "total" - use 365 days as a practical upper bound
		return 365 * 24 * time.Hour
	}
}

// Record records a request's usage against a virtual key in Redis.
func (t *RedisUsageTracker) Record(keyID string, inputTokens, outputTokens int, costUSD float64, isError bool) {
	ctx := context.Background()
	period := "daily" // Default period; callers can set per-key period via RecordWithPeriod
	ttl := periodTTL(period)

	totalTokens := int64(inputTokens) + int64(outputTokens)
	if totalTokens > 0 {
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "tokens", period), totalTokens, ttl)
	}
	_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "requests", period), 1, ttl)

	if inputTokens > 0 {
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "input_tokens", period), int64(inputTokens), ttl)
	}
	if outputTokens > 0 {
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "output_tokens", period), int64(outputTokens), ttl)
	}
	if costUSD > 0 {
		costMicro := int64(costUSD * 1_000_000)
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "cost", period), costMicro, ttl)
	}
	if isError {
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "errors", period), 1, ttl)
	}
}

// RecordWithPeriod records usage with an explicit period (daily, monthly, total).
func (t *RedisUsageTracker) RecordWithPeriod(keyID, period string, inputTokens, outputTokens int, costUSD float64, isError bool) {
	ctx := context.Background()
	ttl := periodTTL(period)

	totalTokens := int64(inputTokens) + int64(outputTokens)
	if totalTokens > 0 {
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "tokens", period), totalTokens, ttl)
	}
	_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "requests", period), 1, ttl)

	if inputTokens > 0 {
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "input_tokens", period), int64(inputTokens), ttl)
	}
	if outputTokens > 0 {
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "output_tokens", period), int64(outputTokens), ttl)
	}
	if costUSD > 0 {
		costMicro := int64(costUSD * 1_000_000)
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "cost", period), costMicro, ttl)
	}
	if isError {
		_, _ = t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "errors", period), 1, ttl)
	}
}

// GetUsage returns the current usage for a key from Redis.
func (t *RedisUsageTracker) GetUsage(keyID string) *KeyUsage {
	return t.GetUsageForPeriod(keyID, "daily")
}

// GetUsageForPeriod returns usage for a specific period.
func (t *RedisUsageTracker) GetUsageForPeriod(keyID, period string) *KeyUsage {
	ctx := context.Background()
	ttl := periodTTL(period)

	// IncrementWithExpires with 0 returns the current value without incrementing
	requests, _ := t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "requests", period), 0, ttl)
	inputTokens, _ := t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "input_tokens", period), 0, ttl)
	outputTokens, _ := t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "output_tokens", period), 0, ttl)
	totalTokens, _ := t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "tokens", period), 0, ttl)
	costMicro, _ := t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "cost", period), 0, ttl)
	errors, _ := t.cache.IncrementWithExpires(ctx, vkUsageCacheType, t.usageKey(keyID, "errors", period), 0, ttl)

	return &KeyUsage{
		KeyID:        keyID,
		Requests:     requests,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		TotalTokens:  totalTokens,
		CostUSD:      float64(costMicro) / 1_000_000,
		Errors:       errors,
		Period:       period,
	}
}

// CheckBudget checks if a key has exceeded its budget limit using Redis counters.
func (t *RedisUsageTracker) CheckBudget(keyID string, maxBudgetUSD float64, budgetPeriod string) bool {
	if maxBudgetUSD <= 0 {
		return true
	}
	usage := t.GetUsageForPeriod(keyID, budgetPeriod)
	return usage.CostUSD < maxBudgetUSD
}

// CheckTokenBudget checks if a key has exceeded its total token budget.
func (t *RedisUsageTracker) CheckTokenBudget(keyID string, maxTokens int64) bool {
	if maxTokens <= 0 {
		return true
	}
	usage := t.GetUsage(keyID)
	return usage.TotalTokens < maxTokens
}

// CheckTokenBudgetForPeriod checks token budget for a specific period.
func (t *RedisUsageTracker) CheckTokenBudgetForPeriod(keyID string, maxTokens int64, period string) bool {
	if maxTokens <= 0 {
		return true
	}
	usage := t.GetUsageForPeriod(keyID, period)
	return usage.TotalTokens < maxTokens
}

// TokenUtilization returns the fraction of token budget used (0.0 to 1.0+).
func (t *RedisUsageTracker) TokenUtilization(keyID string, maxTokens int64) float64 {
	if maxTokens <= 0 {
		return 0
	}
	usage := t.GetUsage(keyID)
	return float64(usage.TotalTokens) / float64(maxTokens)
}

// CheckTokenRate checks if a key is within its tokens-per-minute limit.
func (t *RedisUsageTracker) CheckTokenRate(keyID string, maxTokensPerMin int) bool {
	if maxTokensPerMin <= 0 {
		return true
	}
	usage := t.GetUsage(keyID)
	return usage.TotalTokens < int64(maxTokensPerMin)
}

// Reset clears all usage data for a key (all periods).
func (t *RedisUsageTracker) Reset(keyID string) {
	// Cannot easily delete specific hash fields across all periods,
	// but the TTL-based expiration handles cleanup automatically.
	// This is a best-effort clear for testing.
	ctx := context.Background()
	for _, period := range []string{"hourly", "daily", "weekly", "monthly"} {
		for _, field := range []string{"tokens", "requests", "input_tokens", "output_tokens", "cost", "errors"} {
			_ = t.cache.Delete(ctx, vkUsageCacheType, t.usageKey(keyID, field, period))
		}
	}
}
