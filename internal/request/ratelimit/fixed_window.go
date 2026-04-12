// Package ratelimit implements token bucket and sliding window rate limiting algorithms.
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// FixedWindow implements the fixed window rate limiting algorithm
// Simple and memory-efficient, but allows bursts at window boundaries
type FixedWindow struct {
	cache  cacher.Cacher
	prefix string
	mu     sync.RWMutex

	// Metrics
	allowedCount int64
	deniedCount  int64
	errorCount   int64
}

// NewFixedWindow creates a new fixed window rate limiter
func NewFixedWindow(cache cacher.Cacher, prefix string) *FixedWindow {
	if prefix == "" {
		prefix = "fw"
	}

	return &FixedWindow{
		cache:  cache,
		prefix: prefix,
	}
}

// Algorithm returns the algorithm type
func (fw *FixedWindow) Algorithm() AlgorithmType {
	return AlgorithmFixedWindow
}

// Allow checks if a request is allowed
func (fw *FixedWindow) Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	return fw.AllowN(ctx, key, 1, limit, window)
}

// AllowN checks if N requests are allowed
func (fw *FixedWindow) AllowN(ctx context.Context, key string, n int, limit int, window time.Duration) (Result, error) {
	if n <= 0 {
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: time.Now().Add(window),
		}, nil
	}

	if fw.cache == nil {
		// Fail open if cache unavailable
		slog.Warn("fixed window cache unavailable, allowing request", "key", key)
		fw.mu.Lock()
		fw.allowedCount++
		fw.mu.Unlock()
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: time.Now().Add(window),
		}, nil
	}

	fullKey := fmt.Sprintf("%s:%s", fw.prefix, key)
	now := time.Now()

	// Calculate window start time
	windowStart := now.Truncate(window)
	windowKey := fmt.Sprintf("%s:%d", fullKey, windowStart.Unix())

	// Increment first, then check the returned count to avoid TOCTOU race.
	newCount, err := fw.cache.IncrementWithExpires(ctx, CacheTypeRateLimit, windowKey, int64(n), window+time.Second)
	if err != nil {
		fw.mu.Lock()
		fw.errorCount++
		fw.mu.Unlock()
		slog.Error("failed to increment fixed window count", "key", key, "error", err)
		// Fail open
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: windowStart.Add(window),
		}, err
	}

	resetTime := windowStart.Add(window)

	// Check if limit is exceeded after increment
	if newCount > int64(limit) {
		fw.mu.Lock()
		fw.deniedCount++
		fw.mu.Unlock()

		retryAfter := resetTime.Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}

		return Result{
			Allowed:    false,
			Remaining:  0,
			ResetTime:  resetTime,
			RetryAfter: retryAfter,
		}, nil
	}

	remaining := int(int64(limit) - newCount)
	if remaining < 0 {
		remaining = 0
	}

	fw.mu.Lock()
	fw.allowedCount++
	fw.mu.Unlock()

	return Result{
		Allowed:   true,
		Remaining: remaining,
		ResetTime: resetTime,
	}, nil
}

// GetRemaining returns remaining capacity without consuming
func (fw *FixedWindow) GetRemaining(ctx context.Context, key string, limit int, window time.Duration) (int, error) {
	if fw.cache == nil {
		return limit, nil
	}

	fullKey := fmt.Sprintf("%s:%s", fw.prefix, key)
	now := time.Now()

	// Calculate window start time
	windowStart := now.Truncate(window)
	windowKey := fmt.Sprintf("%s:%d", fullKey, windowStart.Unix())

	// Get current count
	currentCount, err := fw.cache.Increment(ctx, CacheTypeRateLimit, windowKey, 0)
	if err != nil {
		return 0, err
	}

	remaining := int(int64(limit) - currentCount)
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}

// Reset resets the fixed window for a key
func (fw *FixedWindow) Reset(ctx context.Context, key string) error {
	if fw.cache == nil {
		return fmt.Errorf("fixed window cache unavailable")
	}

	fullKey := fmt.Sprintf("%s:%s", fw.prefix, key)

	// Delete all keys matching the pattern
	pattern := fmt.Sprintf("%s:*", fullKey)
	err := fw.cache.DeleteByPattern(ctx, CacheTypeRateLimit, pattern)
	if err != nil {
		return fmt.Errorf("failed to reset fixed window: %w", err)
	}

	slog.Info("fixed window reset", "key", key)
	return nil
}

// GetStats returns rate limiter statistics
func (fw *FixedWindow) GetStats() RateLimiterStats {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	return RateLimiterStats{
		AllowedCount: fw.allowedCount,
		DeniedCount:  fw.deniedCount,
		ErrorCount:   fw.errorCount,
	}
}

