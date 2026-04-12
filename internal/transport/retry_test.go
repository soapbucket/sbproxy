package transport

import (
	"testing"
	"time"
)

func TestRetryBudget_AllowsRetries(t *testing.T) {
	rb := NewRetryBudget(0.2, 10*time.Second)
	defer rb.Close()

	// Record 10 requests, 1 retry = 10% ratio, under 20% budget.
	for range 10 {
		rb.RecordRequest()
	}
	rb.RecordRetry()

	if !rb.AllowRetry() {
		t.Fatal("expected retry to be allowed at 10% ratio with 20% budget")
	}
}

func TestRetryBudget_DeniesOverBudget(t *testing.T) {
	rb := NewRetryBudget(0.1, 10*time.Second)
	defer rb.Close()

	// Record 10 requests, 2 retries = 20% ratio, over 10% budget.
	for range 10 {
		rb.RecordRequest()
	}
	rb.RecordRetry()
	rb.RecordRetry()

	if rb.AllowRetry() {
		t.Fatal("expected retry to be denied at 20% ratio with 10% budget")
	}
}

func TestRetryBudget_ColdStart(t *testing.T) {
	rb := NewRetryBudget(0.1, 10*time.Second)
	defer rb.Close()

	// No requests recorded yet - should allow retries.
	if !rb.AllowRetry() {
		t.Fatal("expected retry to be allowed during cold start (zero requests)")
	}
}

func TestRetryBudget_WindowReset(t *testing.T) {
	rb := NewRetryBudget(0.1, 50*time.Millisecond)
	defer rb.Close()

	// Exceed the budget.
	for range 10 {
		rb.RecordRequest()
	}
	for range 5 {
		rb.RecordRetry()
	}
	if rb.AllowRetry() {
		t.Fatal("expected retry to be denied before window reset")
	}

	// Wait for the window to reset.
	time.Sleep(80 * time.Millisecond)

	// After reset, counters are zeroed - cold start allows retries.
	if !rb.AllowRetry() {
		t.Fatal("expected retry to be allowed after window reset")
	}
}
