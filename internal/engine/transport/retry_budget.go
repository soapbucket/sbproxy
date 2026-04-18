// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"sync"
	"time"
)

// RetryBudget limits the percentage of requests that can be retries within a
// sliding window. This prevents retry storms from overwhelming upstreams when
// they are already under pressure.
type RetryBudget struct {
	mu          sync.Mutex
	maxPercent  float64 // max retry percentage (e.g., 0.20 = 20%)
	window      time.Duration
	totalCount  int64
	retryCount  int64
	windowStart time.Time
}

// NewRetryBudget creates a RetryBudget that allows up to maxPercent of requests
// to be retries within the given window. For example, NewRetryBudget(0.20, time.Minute)
// allows at most 20% of requests in any 1-minute window to be retries.
func NewRetryBudget(maxPercent float64, window time.Duration) *RetryBudget {
	if maxPercent < 0 {
		maxPercent = 0
	}
	if maxPercent > 1.0 {
		maxPercent = 1.0
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RetryBudget{
		maxPercent:  maxPercent,
		window:      window,
		windowStart: time.Now(),
	}
}

// resetIfNeeded resets counters when the current window has expired.
// Caller must hold rb.mu.
func (rb *RetryBudget) resetIfNeeded() {
	now := time.Now()
	if now.Sub(rb.windowStart) >= rb.window {
		rb.totalCount = 0
		rb.retryCount = 0
		rb.windowStart = now
	}
}

// AllowRetry returns true if retrying is within budget. It does not record
// the retry - call RecordRetry separately when the retry is actually issued.
func (rb *RetryBudget) AllowRetry() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.resetIfNeeded()

	// Always allow at least a few retries to avoid total starvation.
	// If fewer than 10 total requests have been seen, allow the retry.
	if rb.totalCount < 10 {
		return true
	}

	// Check if adding one more retry would exceed the budget.
	newRetries := rb.retryCount + 1
	newTotal := rb.totalCount + 1
	return float64(newRetries)/float64(newTotal) <= rb.maxPercent
}

// RecordRequest records a primary (non-retry) request.
func (rb *RetryBudget) RecordRequest() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.resetIfNeeded()
	rb.totalCount++
}

// RecordRetry records a retry attempt. This should be called when a retry
// is actually dispatched (after AllowRetry returns true).
func (rb *RetryBudget) RecordRetry() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.resetIfNeeded()
	rb.totalCount++
	rb.retryCount++
}

// Stats returns current retry stats: total requests, retry count, and the
// current retry percentage within the window.
func (rb *RetryBudget) Stats() (total, retries int64, pct float64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.resetIfNeeded()

	total = rb.totalCount
	retries = rb.retryCount
	if total > 0 {
		pct = float64(retries) / float64(total)
	}
	return total, retries, pct
}
