// Package ratelimit implements token bucket and sliding window rate limiting algorithms.
package ratelimit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// TokenBucket implements the token bucket rate limiting algorithm
// Allows bursts up to capacity while maintaining average rate
type TokenBucket struct {
	cache      cacher.Cacher
	prefix     string
	capacity   int64   // Max tokens in bucket
	refillRate float64 // Tokens per second
	mu         sync.RWMutex

	// Metrics
	allowedCount int64
	deniedCount  int64
	errorCount   int64
}

// tokenBucketState represents the state stored in cache
type tokenBucketState struct {
	Tokens   float64   `json:"tokens"`
	LastRefill time.Time `json:"last_refill"`
}

// NewTokenBucket creates a new token bucket rate limiter
func NewTokenBucket(cache cacher.Cacher, prefix string, capacity int64, refillRate float64) *TokenBucket {
	if prefix == "" {
		prefix = "tb"
	}
	if capacity <= 0 {
		capacity = 100
	}
	if refillRate <= 0 {
		refillRate = 1.0
	}

	return &TokenBucket{
		cache:      cache,
		prefix:     prefix,
		capacity:   capacity,
		refillRate: refillRate,
	}
}

// Algorithm returns the algorithm type
func (tb *TokenBucket) Algorithm() AlgorithmType {
	return AlgorithmTokenBucket
}

// Allow checks if a request is allowed (consumes 1 token)
func (tb *TokenBucket) Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	return tb.AllowN(ctx, key, 1, limit, window)
}

// AllowN checks if N requests are allowed (consumes N tokens)
func (tb *TokenBucket) AllowN(ctx context.Context, key string, n int, limit int, window time.Duration) (Result, error) {
	if n <= 0 {
		return Result{
			Allowed:   true,
			Remaining:  limit,
			ResetTime: time.Now().Add(window),
		}, nil
	}

	if tb.cache == nil {
		// Fail open if cache unavailable
		slog.Warn("token bucket cache unavailable, allowing request", "key", key)
		tb.mu.Lock()
		tb.allowedCount++
		tb.mu.Unlock()
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: time.Now().Add(window),
		}, nil
	}

	// Use limit as capacity if not explicitly set
	capacity := tb.capacity
	if capacity == 0 || capacity > int64(limit) {
		capacity = int64(limit)
	}

	// Calculate refill rate from window and limit
	refillRate := tb.refillRate
	if refillRate == 0 {
		refillRate = float64(limit) / window.Seconds()
	}

	fullKey := fmt.Sprintf("%s:%s", tb.prefix, key)
	now := time.Now()

	// Load current state
	state, err := tb.loadState(ctx, fullKey)
	if err != nil && err != cacher.ErrNotFound {
		tb.mu.Lock()
		tb.errorCount++
		tb.mu.Unlock()
		slog.Error("failed to load token bucket state", "key", key, "error", err)
		// Fail open
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: now.Add(window),
		}, err
	}

	// Refill tokens based on elapsed time
	if err == nil {
		elapsed := now.Sub(state.LastRefill).Seconds()
		state.Tokens = math.Min(float64(capacity), state.Tokens+refillRate*elapsed)
		state.LastRefill = now
	} else {
		// Initialize new bucket
		state = tokenBucketState{
			Tokens:    float64(capacity),
			LastRefill: now,
		}
	}

	// Check if we have enough tokens
	if state.Tokens < float64(n) {
		// Not enough tokens
		needed := float64(n) - state.Tokens
		retryAfter := time.Duration(needed/refillRate) * time.Second

		tb.mu.Lock()
		tb.deniedCount++
		tb.mu.Unlock()

		return Result{
			Allowed:    false,
			Remaining:  0,
			ResetTime:  now.Add(retryAfter),
			RetryAfter: retryAfter,
		}, nil
	}

	// Consume tokens
	state.Tokens -= float64(n)
	remaining := int(state.Tokens)
	if remaining < 0 {
		remaining = 0
	}

	// Save state
	ttl := window + time.Second
	if err := tb.saveState(ctx, fullKey, state, ttl); err != nil {
		tb.mu.Lock()
		tb.errorCount++
		tb.mu.Unlock()
		slog.Error("failed to save token bucket state", "key", key, "error", err)
		// Still allow the request
	}

	tb.mu.Lock()
	tb.allowedCount++
	tb.mu.Unlock()

	// Calculate reset time (when bucket will be full)
	timeToFull := (float64(capacity) - state.Tokens) / refillRate
	resetTime := now.Add(time.Duration(timeToFull) * time.Second)

	return Result{
		Allowed:   true,
		Remaining: remaining,
		ResetTime: resetTime,
	}, nil
}

// GetRemaining returns remaining tokens without consuming them
func (tb *TokenBucket) GetRemaining(ctx context.Context, key string, limit int, window time.Duration) (int, error) {
	if tb.cache == nil {
		return limit, nil
	}

	fullKey := fmt.Sprintf("%s:%s", tb.prefix, key)
	now := time.Now()

	state, err := tb.loadState(ctx, fullKey)
	if err != nil {
		if err == cacher.ErrNotFound {
			capacity := tb.capacity
			if capacity == 0 || capacity > int64(limit) {
				capacity = int64(limit)
			}
			return int(capacity), nil
		}
		return 0, err
	}

	// Refill tokens
	refillRate := tb.refillRate
	if refillRate == 0 {
		refillRate = float64(limit) / window.Seconds()
	}
	capacity := tb.capacity
	if capacity == 0 || capacity > int64(limit) {
		capacity = int64(limit)
	}

	elapsed := now.Sub(state.LastRefill).Seconds()
	tokens := math.Min(float64(capacity), state.Tokens+refillRate*elapsed)

	return int(tokens), nil
}

// Reset resets the token bucket for a key
func (tb *TokenBucket) Reset(ctx context.Context, key string) error {
	if tb.cache == nil {
		return fmt.Errorf("token bucket cache unavailable")
	}

	fullKey := fmt.Sprintf("%s:%s", tb.prefix, key)
	err := tb.cache.Delete(ctx, CacheTypeRateLimit, fullKey)
	if err != nil {
		return fmt.Errorf("failed to reset token bucket: %w", err)
	}

	slog.Info("token bucket reset", "key", key)
	return nil
}

// GetStats returns rate limiter statistics
func (tb *TokenBucket) GetStats() RateLimiterStats {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	return RateLimiterStats{
		AllowedCount: tb.allowedCount,
		DeniedCount:  tb.deniedCount,
		ErrorCount:   tb.errorCount,
	}
}

// loadState loads token bucket state from cache
func (tb *TokenBucket) loadState(ctx context.Context, key string) (tokenBucketState, error) {
	reader, err := tb.cache.Get(ctx, CacheTypeRateLimit, key)
	if err != nil {
		return tokenBucketState{}, err
	}
	if closer, ok := reader.(io.Closer); ok {
		defer closer.Close()
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return tokenBucketState{}, err
	}

	var state tokenBucketState
	if err := json.Unmarshal(data, &state); err != nil {
		return tokenBucketState{}, err
	}

	return state, nil
}

// saveState saves token bucket state to cache
func (tb *TokenBucket) saveState(ctx context.Context, key string, state tokenBucketState, ttl time.Duration) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	return tb.cache.PutWithExpires(ctx, CacheTypeRateLimit, key, bytes.NewReader(data), ttl)
}

