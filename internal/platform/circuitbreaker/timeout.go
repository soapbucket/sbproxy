// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package circuitbreaker

import (
	"context"
	"time"
)

// TimeoutConfig configures timeout behavior
type TimeoutConfig struct {
	Timeout time.Duration
}

// WithTimeoutFunc executes a function with a timeout
func WithTimeoutFunc(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	if timeout == 0 {
		return fn(ctx)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- fn(ctx)
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TimeoutAfter returns an error if the channel doesn't receive within timeout
func TimeoutAfter(timeout time.Duration) <-chan time.Time {
	return time.After(timeout)
}

// Sleep sleeps for a duration, respecting context cancellation
func Sleep(ctx context.Context, duration time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(duration):
		return nil
	}
}
