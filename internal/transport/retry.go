// retry.go implements a retry budget that caps the retry-to-request ratio over a rolling window.
package transport

import (
	"sync/atomic"
	"time"
)

// RetryBudget tracks the ratio of retries to total requests over a rolling
// window. When the ratio exceeds the configured maximum, further retries are
// denied. This prevents retry storms from amplifying failures.
type RetryBudget struct {
	maxRetryRatio float64
	requests      atomic.Int64
	retries       atomic.Int64
	done          chan struct{}
}

// NewRetryBudget creates a RetryBudget that allows retries as long as the
// retry-to-request ratio stays below maxRatio. Counters reset every window
// period. Call Close() to stop the background goroutine.
func NewRetryBudget(maxRatio float64, window time.Duration) *RetryBudget {
	rb := &RetryBudget{
		maxRetryRatio: maxRatio,
		done:          make(chan struct{}),
	}

	ticker := time.NewTicker(window)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rb.requests.Store(0)
				rb.retries.Store(0)
			case <-rb.done:
				return
			}
		}
	}()

	return rb
}

// RecordRequest increments the total request counter.
func (rb *RetryBudget) RecordRequest() {
	rb.requests.Add(1)
}

// RecordRetry increments the retry counter.
func (rb *RetryBudget) RecordRetry() {
	rb.retries.Add(1)
}

// AllowRetry reports whether a retry is permitted under the current budget.
// It returns true when there are no recorded requests (cold start) or when
// the retry ratio is below the configured maximum.
func (rb *RetryBudget) AllowRetry() bool {
	reqs := rb.requests.Load()
	if reqs == 0 {
		return true
	}
	retries := rb.retries.Load()
	return float64(retries)/float64(reqs) < rb.maxRetryRatio
}

// Close stops the background window-reset goroutine.
func (rb *RetryBudget) Close() {
	close(rb.done)
}
