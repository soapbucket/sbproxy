// Package ratelimit implements token bucket and sliding window rate limiting algorithms.
package ratelimit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// LeakyBucket implements the leaky bucket rate limiting algorithm
// Strict rate limiting with no burst tolerance
type LeakyBucket struct {
	cache     cacher.Cacher
	prefix    string
	queueSize int     // Max queue size
	drainRate float64 // Requests per second
	mu        sync.RWMutex

	// Metrics
	allowedCount int64
	deniedCount  int64
	errorCount   int64
}

// leakyBucketState represents the state stored in cache
type leakyBucketState struct {
	QueueLength int       `json:"queue_length"`
	LastDrain   time.Time `json:"last_drain"`
}

// NewLeakyBucket creates a new leaky bucket rate limiter
func NewLeakyBucket(cache cacher.Cacher, prefix string, queueSize int, drainRate float64) *LeakyBucket {
	if prefix == "" {
		prefix = "lb"
	}
	if queueSize <= 0 {
		queueSize = 100
	}
	if drainRate <= 0 {
		drainRate = 1.0
	}

	return &LeakyBucket{
		cache:     cache,
		prefix:    prefix,
		queueSize: queueSize,
		drainRate: drainRate,
	}
}

// Algorithm returns the algorithm type
func (lb *LeakyBucket) Algorithm() AlgorithmType {
	return AlgorithmLeakyBucket
}

// Allow checks if a request is allowed (adds 1 to queue)
func (lb *LeakyBucket) Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	return lb.AllowN(ctx, key, 1, limit, window)
}

// AllowN checks if N requests are allowed (adds N to queue)
func (lb *LeakyBucket) AllowN(ctx context.Context, key string, n int, limit int, window time.Duration) (Result, error) {
	if n <= 0 {
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: time.Now().Add(window),
		}, nil
	}

	if lb.cache == nil {
		// Fail open if cache unavailable
		slog.Warn("leaky bucket cache unavailable, allowing request", "key", key)
		lb.mu.Lock()
		lb.allowedCount++
		lb.mu.Unlock()
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: time.Now().Add(window),
		}, nil
	}

	// Use limit as queue size if not explicitly set
	queueSize := lb.queueSize
	if queueSize == 0 || queueSize > limit {
		queueSize = limit
	}

	// Calculate drain rate from window and limit
	drainRate := lb.drainRate
	if drainRate == 0 {
		drainRate = float64(limit) / window.Seconds()
	}

	fullKey := fmt.Sprintf("%s:%s", lb.prefix, key)
	now := time.Now()

	// Load current state
	state, err := lb.loadState(ctx, fullKey)
	if err != nil && err != cacher.ErrNotFound {
		lb.mu.Lock()
		lb.errorCount++
		lb.mu.Unlock()
		slog.Error("failed to load leaky bucket state", "key", key, "error", err)
		// Fail open
		return Result{
			Allowed:   true,
			Remaining: limit,
			ResetTime: now.Add(window),
		}, err
	}

	// Drain queue based on elapsed time
	if err == nil {
		elapsed := now.Sub(state.LastDrain).Seconds()
		drained := int(drainRate * elapsed)
		if drained > 0 {
			state.QueueLength -= drained
			if state.QueueLength < 0 {
				state.QueueLength = 0
			}
			state.LastDrain = now
		}
	} else {
		// Initialize new bucket
		state = leakyBucketState{
			QueueLength: 0,
			LastDrain:   now,
		}
	}

	// Check if queue has space
	if state.QueueLength+n > queueSize {
		// Queue full, calculate retry after
		spaceNeeded := (state.QueueLength + n) - queueSize
		retryAfter := time.Duration(float64(spaceNeeded)/drainRate) * time.Second

		lb.mu.Lock()
		lb.deniedCount++
		lb.mu.Unlock()

		return Result{
			Allowed:    false,
			Remaining:  0,
			ResetTime:  now.Add(retryAfter),
			RetryAfter: retryAfter,
		}, nil
	}

	// Add to queue
	state.QueueLength += n
	remaining := queueSize - state.QueueLength
	if remaining < 0 {
		remaining = 0
	}

	// Save state
	ttl := window + time.Second
	if err := lb.saveState(ctx, fullKey, state, ttl); err != nil {
		lb.mu.Lock()
		lb.errorCount++
		lb.mu.Unlock()
		slog.Error("failed to save leaky bucket state", "key", key, "error", err)
		// Still allow the request
	}

	lb.mu.Lock()
	lb.allowedCount++
	lb.mu.Unlock()

	// Calculate reset time (when queue will be empty)
	timeToEmpty := float64(state.QueueLength) / drainRate
	resetTime := now.Add(time.Duration(timeToEmpty) * time.Second)

	return Result{
		Allowed:   true,
		Remaining: remaining,
		ResetTime: resetTime,
	}, nil
}

// GetRemaining returns remaining queue capacity without adding to queue
func (lb *LeakyBucket) GetRemaining(ctx context.Context, key string, limit int, window time.Duration) (int, error) {
	if lb.cache == nil {
		return limit, nil
	}

	fullKey := fmt.Sprintf("%s:%s", lb.prefix, key)
	now := time.Now()

	state, err := lb.loadState(ctx, fullKey)
	if err != nil {
		if err == cacher.ErrNotFound {
			queueSize := lb.queueSize
			if queueSize == 0 || queueSize > limit {
				queueSize = limit
			}
			return queueSize, nil
		}
		return 0, err
	}

	// Drain queue
	drainRate := lb.drainRate
	if drainRate == 0 {
		drainRate = float64(limit) / window.Seconds()
	}
	queueSize := lb.queueSize
	if queueSize == 0 || queueSize > limit {
		queueSize = limit
	}

	elapsed := now.Sub(state.LastDrain).Seconds()
	drained := int(drainRate * elapsed)
	queueLength := state.QueueLength - drained
	if queueLength < 0 {
		queueLength = 0
	}

	remaining := queueSize - queueLength
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}

// Reset resets the leaky bucket for a key
func (lb *LeakyBucket) Reset(ctx context.Context, key string) error {
	if lb.cache == nil {
		return fmt.Errorf("leaky bucket cache unavailable")
	}

	fullKey := fmt.Sprintf("%s:%s", lb.prefix, key)
	err := lb.cache.Delete(ctx, CacheTypeRateLimit, fullKey)
	if err != nil {
		return fmt.Errorf("failed to reset leaky bucket: %w", err)
	}

	slog.Info("leaky bucket reset", "key", key)
	return nil
}

// GetStats returns rate limiter statistics
func (lb *LeakyBucket) GetStats() RateLimiterStats {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	return RateLimiterStats{
		AllowedCount: lb.allowedCount,
		DeniedCount:  lb.deniedCount,
		ErrorCount:   lb.errorCount,
	}
}

// loadState loads leaky bucket state from cache
func (lb *LeakyBucket) loadState(ctx context.Context, key string) (leakyBucketState, error) {
	reader, err := lb.cache.Get(ctx, CacheTypeRateLimit, key)
	if err != nil {
		return leakyBucketState{}, err
	}
	if closer, ok := reader.(io.Closer); ok {
		defer closer.Close()
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return leakyBucketState{}, err
	}

	var state leakyBucketState
	if err := json.Unmarshal(data, &state); err != nil {
		return leakyBucketState{}, err
	}

	return state, nil
}

// saveState saves leaky bucket state to cache
func (lb *LeakyBucket) saveState(ctx context.Context, key string, state leakyBucketState, ttl time.Duration) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	return lb.cache.PutWithExpires(ctx, CacheTypeRateLimit, key, bytes.NewReader(data), ttl)
}
