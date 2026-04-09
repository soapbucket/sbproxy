// Package ratelimit implements token bucket and sliding window rate limiting algorithms.
package ratelimit

import (
	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// NewRateLimiter creates a new rate limiter based on algorithm type
func NewRateLimiter(cache cacher.Cacher, algorithm AlgorithmType, prefix string, config Config) RateLimiter {
	if prefix == "" {
		prefix = "rl"
	}

	switch algorithm {
	case AlgorithmTokenBucket:
		return NewTokenBucket(cache, prefix, int64(config.BurstSize), config.RefillRate)
	case AlgorithmLeakyBucket:
		return NewLeakyBucket(cache, prefix, config.QueueSize, config.DrainRate)
	case AlgorithmFixedWindow:
		return NewFixedWindow(cache, prefix)
	case AlgorithmSlidingWindow:
		fallthrough
	default:
		return NewDistributedRateLimiter(cache, prefix)
	}
}

