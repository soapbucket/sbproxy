// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package circuitbreaker

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// RetryConfig configures retry behavior
type RetryConfig struct {
	MaxAttempts   int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	Multiplier    float64
	Jitter        float64
	RetryableFunc func(error) bool
}

// DefaultRetryConfig returns a retry config with sensible defaults
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.1,
	}
}

// Retry executes a function with retry logic
func Retry(ctx context.Context, config *RetryConfig, fn func() error) error {
	if config == nil {
		config = DefaultRetryConfig()
	}

	var lastErr error
	delay := config.InitialDelay

	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		// Execute function
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if config.RetryableFunc != nil && !config.RetryableFunc(err) {
			return err
		}

		// Don't sleep after last attempt
		if attempt == config.MaxAttempts-1 {
			break
		}

		// Calculate delay with jitter
		actualDelay := addJitter(delay, config.Jitter)

		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(actualDelay):
		}

		// Exponential backoff
		delay = time.Duration(float64(delay) * config.Multiplier)
		if delay > config.MaxDelay {
			delay = config.MaxDelay
		}
	}

	return lastErr
}

// addJitter adds random jitter to a duration
func addJitter(duration time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return duration
	}

	// Add random jitter between -jitter% and +jitter%
	jitterAmount := float64(duration) * jitter
	randomJitter := (rand.Float64()*2 - 1) * jitterAmount
	return time.Duration(float64(duration) + randomJitter)
}

// ExponentialBackoff calculates backoff duration for an attempt
func ExponentialBackoff(attempt int, initialDelay, maxDelay time.Duration, multiplier float64) time.Duration {
	delay := float64(initialDelay) * math.Pow(multiplier, float64(attempt))
	if delay > float64(maxDelay) {
		return maxDelay
	}
	return time.Duration(delay)
}
