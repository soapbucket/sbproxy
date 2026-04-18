package transport

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetryBudget_AllowsRetriesUnderBudget(t *testing.T) {
	rb := NewRetryBudget(0.20, time.Minute)

	// Record 100 primary requests
	for i := 0; i < 100; i++ {
		rb.RecordRequest()
	}

	// Should allow retries up to 20% of total
	for i := 0; i < 20; i++ {
		assert.True(t, rb.AllowRetry(), "retry %d should be allowed", i)
		rb.RecordRetry()
	}

	// 21st retry would push us past 20% (21/121 = 17.3%, but 20/120 = 16.7%)
	// At this point we have 120 total, 20 retries = 16.7%, one more = 21/121 = 17.4%
	// Still under 20%, so it should be allowed
	assert.True(t, rb.AllowRetry())
}

func TestRetryBudget_BlocksRetriesOverBudget(t *testing.T) {
	rb := NewRetryBudget(0.10, time.Minute)

	// Record 50 primary requests
	for i := 0; i < 50; i++ {
		rb.RecordRequest()
	}

	// Record 5 retries (5/55 = 9.1%, under 10%)
	for i := 0; i < 5; i++ {
		assert.True(t, rb.AllowRetry())
		rb.RecordRetry()
	}

	// Now: 55 total, 5 retries. Next retry would be 6/56 = 10.7%, over 10%
	assert.False(t, rb.AllowRetry())
}

func TestRetryBudget_AllowsSmallBatch(t *testing.T) {
	rb := NewRetryBudget(0.20, time.Minute)

	// With fewer than 10 total requests, retries are always allowed
	rb.RecordRequest()
	rb.RecordRequest()

	assert.True(t, rb.AllowRetry())
}

func TestRetryBudget_Stats(t *testing.T) {
	rb := NewRetryBudget(0.50, time.Minute)

	rb.RecordRequest()
	rb.RecordRequest()
	rb.RecordRequest()
	rb.RecordRetry()

	total, retries, pct := rb.Stats()
	assert.Equal(t, int64(4), total)
	assert.Equal(t, int64(1), retries)
	assert.InDelta(t, 0.25, pct, 0.01)
}

func TestRetryBudget_WindowReset(t *testing.T) {
	// Use a very short window for testing
	rb := NewRetryBudget(0.10, 50*time.Millisecond)

	// Fill up requests and retries
	for i := 0; i < 50; i++ {
		rb.RecordRequest()
	}
	for i := 0; i < 5; i++ {
		rb.RecordRetry()
	}

	// Should be at budget limit
	assert.False(t, rb.AllowRetry())

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// After window reset, retries should be allowed again
	assert.True(t, rb.AllowRetry())

	total, retries, _ := rb.Stats()
	assert.Equal(t, int64(0), total)
	assert.Equal(t, int64(0), retries)
}

func TestRetryBudget_ClampsValues(t *testing.T) {
	// Negative max percent clamped to 0
	rb := NewRetryBudget(-0.5, time.Minute)
	for i := 0; i < 20; i++ {
		rb.RecordRequest()
	}
	// With 0% budget and enough requests, retries should be blocked
	assert.False(t, rb.AllowRetry())

	// Over 1.0 clamped to 1.0
	rb2 := NewRetryBudget(2.0, time.Minute)
	for i := 0; i < 20; i++ {
		rb2.RecordRequest()
	}
	assert.True(t, rb2.AllowRetry())
}
