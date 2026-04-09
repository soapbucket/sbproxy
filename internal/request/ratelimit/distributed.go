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

const (
	// CacheType for rate limiting entries
	CacheTypeRateLimit = "ratelimit"
)

// DistributedRateLimiter implements a distributed rate limiter using an
// approximate sliding window algorithm. Instead of tracking per-second
// buckets (O(N) reads where N = window seconds), it uses two adjacent
// fixed windows with weighted interpolation for O(2-3) cache operations.
type DistributedRateLimiter struct {
	cache  cacher.Cacher
	prefix string
	mu     sync.RWMutex

	// Metrics
	allowedCount int64
	deniedCount  int64
	errorCount   int64
}

// NewDistributedRateLimiter creates a new distributed rate limiter
func NewDistributedRateLimiter(cache cacher.Cacher, prefix string) *DistributedRateLimiter {
	if prefix == "" {
		prefix = "rl"
	}

	return &DistributedRateLimiter{
		cache:  cache,
		prefix: prefix,
	}
}

// Algorithm returns the algorithm type
func (rl *DistributedRateLimiter) Algorithm() AlgorithmType {
	return AlgorithmSlidingWindow
}

// windowKey returns the cache key for a given window index.
// The window index is computed as unix_seconds / window_seconds.
func windowKey(prefix string, windowIndex int64) string {
	return prefix + ":" + fmt.Sprint(windowIndex)
}

// getWindowCount reads the counter for a window. Returns 0 on error or miss.
func (rl *DistributedRateLimiter) getWindowCount(ctx context.Context, key string) int64 {
	count, err := rl.cache.Increment(ctx, CacheTypeRateLimit, key, 0)
	if err != nil {
		return 0
	}
	return count
}

// estimateCount computes the approximate sliding window count using
// two fixed windows with weighted interpolation:
//
//	estimate = previousCount * (1 - elapsed/windowSec) + currentCount
func (rl *DistributedRateLimiter) estimateCount(ctx context.Context, fullKey string, windowSec int64, now time.Time) int64 {
	currentIndex := now.Unix() / windowSec
	prevIndex := currentIndex - 1

	currentCount := rl.getWindowCount(ctx, windowKey(fullKey, currentIndex))
	prevCount := rl.getWindowCount(ctx, windowKey(fullKey, prevIndex))

	// How far into the current window are we (0.0 to 1.0)
	elapsed := now.Unix() - (currentIndex * windowSec)
	weight := float64(windowSec-elapsed) / float64(windowSec)

	return int64(float64(prevCount)*weight) + currentCount
}

// Allow checks if a request is allowed under the rate limit using the
// approximate sliding window algorithm.
func (rl *DistributedRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	if rl.cache == nil {
		slog.Warn("rate limiter cache unavailable, allowing request", "key", key)
		rl.mu.Lock()
		rl.allowedCount++
		rl.mu.Unlock()
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: time.Now().Add(window),
		}, nil
	}

	fullKey := rl.prefix + ":" + key
	now := time.Now()
	windowSec := int64(window.Seconds())
	if windowSec == 0 {
		windowSec = 1
	}

	// Estimate current count using weighted sliding window
	estimated := rl.estimateCount(ctx, fullKey, windowSec, now)

	// Check if limit would be exceeded
	if estimated >= int64(limit) {
		rl.mu.Lock()
		rl.deniedCount++
		rl.mu.Unlock()

		currentIndex := now.Unix() / windowSec
		resetTime := time.Unix((currentIndex+1)*windowSec, 0)
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

	// Increment counter for current window
	currentIndex := now.Unix() / windowSec
	curKey := windowKey(fullKey, currentIndex)
	newCount, err := rl.cache.IncrementWithExpires(ctx, CacheTypeRateLimit, curKey, 1, window*2)
	if err != nil {
		rl.mu.Lock()
		rl.errorCount++
		rl.mu.Unlock()

		slog.Error("rate limit check failed", "key", key, "error", err)
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: now.Add(window),
		}, err
	}

	// Recalculate estimate with the new count
	prevIndex := currentIndex - 1
	prevCount := rl.getWindowCount(ctx, windowKey(fullKey, prevIndex))
	elapsed := now.Unix() - (currentIndex * windowSec)
	weight := float64(windowSec-elapsed) / float64(windowSec)
	totalEstimate := int64(float64(prevCount)*weight) + newCount

	remaining := int(int64(limit) - totalEstimate)
	if remaining < 0 {
		remaining = 0
	}

	resetTime := time.Unix((currentIndex+1)*windowSec, 0)

	rl.mu.Lock()
	rl.allowedCount++
	rl.mu.Unlock()

	return Result{
		Allowed:   true,
		Remaining: remaining,
		ResetTime: resetTime,
	}, nil
}

// AllowN checks if N requests are allowed under the rate limit.
// This is useful for batch operations or weighted rate limiting.
func (rl *DistributedRateLimiter) AllowN(ctx context.Context, key string, n int, limit int, window time.Duration) (Result, error) {
	if n <= 0 {
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: time.Now().Add(window),
		}, nil
	}

	if rl.cache == nil {
		rl.mu.Lock()
		rl.allowedCount += int64(n)
		rl.mu.Unlock()
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: time.Now().Add(window),
		}, nil
	}

	fullKey := rl.prefix + ":" + key
	now := time.Now()
	windowSec := int64(window.Seconds())
	if windowSec == 0 {
		windowSec = 1
	}

	// Estimate current count
	estimated := rl.estimateCount(ctx, fullKey, windowSec, now)

	// Check if adding N would exceed limit
	if estimated+int64(n) > int64(limit) {
		currentIndex := now.Unix() / windowSec
		resetTime := time.Unix((currentIndex+1)*windowSec, 0)
		retryAfter := resetTime.Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}

		rl.mu.Lock()
		rl.deniedCount++
		rl.mu.Unlock()

		return Result{
			Allowed:    false,
			Remaining:  0,
			ResetTime:  resetTime,
			RetryAfter: retryAfter,
		}, nil
	}

	// Increment by N
	currentIndex := now.Unix() / windowSec
	curKey := windowKey(fullKey, currentIndex)
	newCount, err := rl.cache.IncrementWithExpires(ctx, CacheTypeRateLimit, curKey, int64(n), window*2)
	if err != nil {
		rl.mu.Lock()
		rl.errorCount++
		rl.mu.Unlock()
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: now.Add(window),
		}, fmt.Errorf("failed to increment counter: %w", err)
	}

	// Recalculate estimate
	prevIndex := currentIndex - 1
	prevCount := rl.getWindowCount(ctx, windowKey(fullKey, prevIndex))
	elapsed := now.Unix() - (currentIndex * windowSec)
	weight := float64(windowSec-elapsed) / float64(windowSec)
	totalEstimate := int64(float64(prevCount)*weight) + newCount

	remaining := int(int64(limit) - totalEstimate)
	if remaining < 0 {
		remaining = 0
	}

	resetTime := time.Unix((currentIndex+1)*windowSec, 0)

	rl.mu.Lock()
	rl.allowedCount += int64(n)
	rl.mu.Unlock()

	return Result{
		Allowed:   true,
		Remaining: remaining,
		ResetTime: resetTime,
	}, nil
}

// GetRemaining returns remaining capacity without consuming
func (rl *DistributedRateLimiter) GetRemaining(ctx context.Context, key string, limit int, window time.Duration) (int, error) {
	if rl.cache == nil {
		return limit, nil
	}

	fullKey := rl.prefix + ":" + key
	now := time.Now()
	windowSec := int64(window.Seconds())
	if windowSec == 0 {
		windowSec = 1
	}

	estimated := rl.estimateCount(ctx, fullKey, windowSec, now)

	remaining := int(int64(limit) - estimated)
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}

// Reset resets the rate limit for a specific key
func (rl *DistributedRateLimiter) Reset(ctx context.Context, key string) error {
	if rl.cache == nil {
		return fmt.Errorf("rate limiter cache unavailable")
	}

	fullKey := rl.prefix + ":" + key

	// Delete all keys matching the pattern
	pattern := fullKey + ":*"
	err := rl.cache.DeleteByPattern(ctx, CacheTypeRateLimit, pattern)
	if err != nil {
		return fmt.Errorf("failed to reset rate limit: %w", err)
	}

	slog.Info("rate limit reset", "key", key)
	return nil
}

// GetStats returns rate limiter statistics
func (rl *DistributedRateLimiter) GetStats() RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return RateLimiterStats{
		AllowedCount: rl.allowedCount,
		DeniedCount:  rl.deniedCount,
		ErrorCount:   rl.errorCount,
	}
}

// RateLimiterStats contains statistics about rate limiting
type RateLimiterStats struct {
	AllowedCount int64
	DeniedCount  int64
	ErrorCount   int64
}

// AllowRate returns the percentage of allowed requests
func (s RateLimiterStats) AllowRate() float64 {
	total := s.AllowedCount + s.DeniedCount
	if total == 0 {
		return 100.0
	}
	return float64(s.AllowedCount) / float64(total) * 100.0
}

// ErrorRate returns the percentage of errors
func (s RateLimiterStats) ErrorRate() float64 {
	total := s.AllowedCount + s.DeniedCount + s.ErrorCount
	if total == 0 {
		return 0.0
	}
	return float64(s.ErrorCount) / float64(total) * 100.0
}
