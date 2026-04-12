// Package ratelimit implements token bucket and sliding window rate limiting algorithms.
package ratelimit

import (
	"context"
	"time"
)

// AlgorithmType identifies the rate limiting algorithm
type AlgorithmType string

const (
	// AlgorithmSlidingWindow is a constant for algorithm sliding window.
	AlgorithmSlidingWindow AlgorithmType = "sliding_window"
	// AlgorithmTokenBucket is a constant for algorithm token bucket.
	AlgorithmTokenBucket AlgorithmType = "token_bucket"
	// AlgorithmLeakyBucket is a constant for algorithm leaky bucket.
	AlgorithmLeakyBucket AlgorithmType = "leaky_bucket"
	// AlgorithmFixedWindow is a constant for algorithm fixed window.
	AlgorithmFixedWindow AlgorithmType = "fixed_window"
)

// Result contains rate limit check result
type Result struct {
	Allowed    bool          // Whether the request is allowed
	Remaining  int           // Number of requests remaining in window
	ResetTime  time.Time     // When the rate limit resets
	RetryAfter time.Duration // Seconds until retry allowed (for 429 responses)
}

// RateLimiter is the interface for all rate limiting algorithms
type RateLimiter interface {
	// Allow checks if a request is allowed
	Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error)

	// AllowN checks if N requests are allowed (for cost-based limiting)
	AllowN(ctx context.Context, key string, n int, limit int, window time.Duration) (Result, error)

	// GetRemaining returns remaining capacity without consuming tokens
	GetRemaining(ctx context.Context, key string, limit int, window time.Duration) (int, error)

	// Reset resets the rate limit for a key
	Reset(ctx context.Context, key string) error

	// GetStats returns algorithm-specific statistics
	GetStats() RateLimiterStats

	// Algorithm returns the algorithm type
	Algorithm() AlgorithmType
}

// Config holds configuration for rate limiters
type Config struct {
	// Algorithm to use
	Algorithm AlgorithmType

	// Token bucket specific
	BurstSize  int     // Max burst capacity (token bucket)
	RefillRate float64 // Tokens per second (token bucket)

	// Leaky bucket specific
	QueueSize int     // Max queue size (leaky bucket)
	DrainRate float64 // Requests per second (leaky bucket)

	// Storage configuration
	Cache  interface{} // Cacher interface (avoiding circular import)
	Prefix string      // Key prefix for storage
}
