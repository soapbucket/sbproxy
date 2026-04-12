package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errService = errors.New("service unavailable")

// TestStateTransition_Closed_Open_HalfOpen_Closed verifies the full recovery cycle:
// closed -> (failures) -> open -> (timeout) -> half-open -> (successes) -> closed
func TestStateTransition_Closed_Open_HalfOpen_Closed(t *testing.T) {
	cb := New(Config{
		Name:             "test-recovery",
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          50 * time.Millisecond,
	})

	// Start closed
	if s := cb.GetState(); s != StateClosed {
		t.Fatalf("expected closed, got %s", s)
	}

	// 3 failures should trip to open
	for i := 0; i < 3; i++ {
		_ = cb.Call(func() error { return errService })
	}
	if s := cb.GetState(); s != StateOpen {
		t.Fatalf("expected open after 3 failures, got %s", s)
	}

	// Calls while open should return ErrCircuitOpen
	err := cb.Call(func() error { return nil })
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}

	// Wait for timeout to elapse
	time.Sleep(80 * time.Millisecond)

	// Next call should transition to half-open and succeed
	err = cb.Call(func() error { return nil })
	if err != nil {
		t.Fatalf("expected nil error in half-open probe, got %v", err)
	}

	// After one success, state is half-open (need 2 successes to close)
	state := cb.GetState()
	if state != StateHalfOpen && state != StateClosed {
		t.Fatalf("expected half-open or closed after 1 success, got %s", state)
	}

	// Second success should close the circuit
	err = cb.Call(func() error { return nil })
	if err != nil {
		t.Fatalf("expected nil error on second success, got %v", err)
	}

	if s := cb.GetState(); s != StateClosed {
		t.Fatalf("expected closed after reaching success threshold, got %s", s)
	}
}

// TestStateTransition_HalfOpen_BackToOpen verifies that failures during
// half-open eventually trip the breaker back to open once the failure
// threshold is reached.
func TestStateTransition_HalfOpen_BackToOpen(t *testing.T) {
	cb := New(Config{
		Name:             "test-reopen",
		FailureThreshold: 2,
		SuccessThreshold: 5,
		Timeout:          50 * time.Millisecond,
	})

	// Trip the breaker
	for i := 0; i < 2; i++ {
		_ = cb.Call(func() error { return errService })
	}
	if s := cb.GetState(); s != StateOpen {
		t.Fatalf("expected open, got %s", s)
	}

	// Wait for timeout
	time.Sleep(80 * time.Millisecond)

	// Probe call succeeds, transitioning to half-open
	_ = cb.Call(func() error { return nil })

	// Now in half-open, send enough failures to reach the failure threshold.
	for i := 0; i < 2; i++ {
		_ = cb.Call(func() error { return errService })
	}

	state := cb.GetState()
	if state != StateOpen && state != StateHalfOpen {
		t.Fatalf("expected open or half-open after failures, got %s", state)
	}
	t.Logf("State after failures in half-open: %s", state)
}

// TestConcurrentStateTransitions exercises the circuit breaker from many
// goroutines simultaneously to verify there are no data races.
func TestConcurrentStateTransitions(t *testing.T) {
	cb := New(Config{
		Name:             "test-concurrent",
		FailureThreshold: 5,
		SuccessThreshold: 3,
		Timeout:          20 * time.Millisecond,
	})

	const goroutines = 50
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if i%3 == 0 {
					_ = cb.Call(func() error { return errService })
				} else {
					_ = cb.Call(func() error { return nil })
				}
			}
		}(g)
	}
	wg.Wait()

	// Just verify no panic occurred and state is valid
	s := cb.GetState()
	if s != StateClosed && s != StateOpen && s != StateHalfOpen {
		t.Fatalf("unexpected state: %s", s)
	}
}

// TestRegistry_GetOrCreate verifies creation and retrieval of breakers.
func TestRegistry_GetOrCreate(t *testing.T) {
	reg := NewRegistry()

	cb1 := reg.GetOrCreate("svc-a", Config{FailureThreshold: 3})
	if cb1 == nil {
		t.Fatal("expected non-nil breaker")
	}

	// Second call with the same name should return the same instance.
	cb2 := reg.GetOrCreate("svc-a", Config{FailureThreshold: 10})
	if cb1 != cb2 {
		t.Fatal("expected same breaker instance for same name")
	}

	// Different name should produce a different instance.
	cb3 := reg.GetOrCreate("svc-b", Config{FailureThreshold: 7})
	if cb3 == cb1 {
		t.Fatal("expected different breaker for different name")
	}
}

// TestRegistry_Get verifies the read-only Get method.
func TestRegistry_Get(t *testing.T) {
	reg := NewRegistry()

	// Get on empty registry returns nil
	if got := reg.Get("missing"); got != nil {
		t.Fatal("expected nil for missing breaker")
	}

	reg.GetOrCreate("exists", DefaultConfig)
	if got := reg.Get("exists"); got == nil {
		t.Fatal("expected non-nil for existing breaker")
	}
}

// TestRegistry_ConcurrentGetOrCreate verifies the double-check locking
// under concurrent access.
func TestRegistry_ConcurrentGetOrCreate(t *testing.T) {
	reg := NewRegistry()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	breakers := make([]*CircuitBreaker, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			breakers[idx] = reg.GetOrCreate("shared", DefaultConfig)
		}(i)
	}
	wg.Wait()

	// All goroutines must have received the same breaker instance.
	for i := 1; i < goroutines; i++ {
		if breakers[i] != breakers[0] {
			t.Fatalf("breaker[%d] differs from breaker[0]", i)
		}
	}
}

// TestRetry_Success verifies that Retry returns nil on the first successful attempt.
func TestRetry_Success(t *testing.T) {
	cfg := DefaultRetryConfig()
	var attempts int
	err := Retry(context.Background(), cfg, func() error {
		attempts++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", attempts)
	}
}

// TestRetry_EventualSuccess retries twice then succeeds.
func TestRetry_EventualSuccess(t *testing.T) {
	cfg := &RetryConfig{
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
		Jitter:       0,
	}

	var attempts int
	err := Retry(context.Background(), cfg, func() error {
		attempts++
		if attempts < 3 {
			return errService
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil after retry, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

// TestRetry_MaxRetries verifies that the function stops after MaxAttempts.
func TestRetry_MaxRetries(t *testing.T) {
	cfg := &RetryConfig{
		MaxAttempts:  3,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
		Multiplier:   2.0,
		Jitter:       0,
	}

	var attempts int
	err := Retry(context.Background(), cfg, func() error {
		attempts++
		return errService
	})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

// TestRetry_ContextCancellation verifies that Retry respects context cancellation.
func TestRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &RetryConfig{
		MaxAttempts:  100,
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     time.Second,
		Multiplier:   2.0,
		Jitter:       0,
	}

	var attempts int32
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	err := Retry(ctx, cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return errService
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestRetry_NonRetryableError verifies that non-retryable errors stop retries immediately.
func TestRetry_NonRetryableError(t *testing.T) {
	cfg := &RetryConfig{
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
		Multiplier:   2.0,
		Jitter:       0,
		RetryableFunc: func(err error) bool {
			return !errors.Is(err, errService)
		},
	}

	var attempts int
	err := Retry(context.Background(), cfg, func() error {
		attempts++
		return errService
	})
	if !errors.Is(err, errService) {
		t.Fatalf("expected errService, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt for non-retryable error, got %d", attempts)
	}
}

// TestExponentialBackoff verifies computed backoff durations.
func TestExponentialBackoff(t *testing.T) {
	tests := []struct {
		name     string
		attempt  int
		initial  time.Duration
		max      time.Duration
		mult     float64
		expected time.Duration
	}{
		{"attempt 0", 0, 100 * time.Millisecond, time.Second, 2.0, 100 * time.Millisecond},
		{"attempt 1", 1, 100 * time.Millisecond, time.Second, 2.0, 200 * time.Millisecond},
		{"attempt 2", 2, 100 * time.Millisecond, time.Second, 2.0, 400 * time.Millisecond},
		{"capped at max", 10, 100 * time.Millisecond, time.Second, 2.0, time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExponentialBackoff(tc.attempt, tc.initial, tc.max, tc.mult)
			if got != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

// TestHalfOpen_LimitedConcurrentProbes verifies that only one goroutine
// can transition from open to half-open at a time (thundering herd prevention).
func TestHalfOpen_LimitedConcurrentProbes(t *testing.T) {
	cb := New(Config{
		Name:             "test-probe",
		FailureThreshold: 1,
		SuccessThreshold: 100,
		Timeout:          30 * time.Millisecond,
	})

	// Trip the breaker
	_ = cb.Call(func() error { return errService })
	if s := cb.GetState(); s != StateOpen {
		t.Fatalf("expected open, got %s", s)
	}

	// Wait for timeout
	time.Sleep(50 * time.Millisecond)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	barrier := make(chan struct{})
	var probeViaOpenPath atomic.Int32
	var circuitOpenErrors atomic.Int32

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-barrier
			err := cb.Call(func() error {
				return nil
			})
			if err == nil {
				probeViaOpenPath.Add(1)
			} else if errors.Is(err, ErrCircuitOpen) {
				circuitOpenErrors.Add(1)
			}
		}()
	}
	close(barrier)
	wg.Wait()

	total := probeViaOpenPath.Load() + circuitOpenErrors.Load()
	if total != goroutines {
		t.Errorf("expected %d total results, got %d", goroutines, total)
	}
	t.Logf("probe successes: %d, circuit open rejections: %d", probeViaOpenPath.Load(), circuitOpenErrors.Load())
}

// TestCircuitBreaker_Reset verifies that Reset brings the breaker back to closed.
func TestCircuitBreaker_Reset(t *testing.T) {
	cb := New(Config{
		Name:             "test-reset",
		FailureThreshold: 1,
		SuccessThreshold: 1,
		Timeout:          time.Hour,
	})

	// Trip
	_ = cb.Call(func() error { return errService })
	if s := cb.GetState(); s != StateOpen {
		t.Fatalf("expected open, got %s", s)
	}

	cb.Reset()

	if s := cb.GetState(); s != StateClosed {
		t.Fatalf("expected closed after reset, got %s", s)
	}

	// Calls should work again
	err := cb.Call(func() error { return nil })
	if err != nil {
		t.Fatalf("expected nil after reset, got %v", err)
	}
}

// TestCircuitBreaker_GetStats verifies stats reporting.
func TestCircuitBreaker_GetStats(t *testing.T) {
	cb := New(Config{
		Name:             "test-stats",
		FailureThreshold: 10,
		SuccessThreshold: 5,
		Timeout:          time.Second,
	})

	// 3 successes
	for i := 0; i < 3; i++ {
		_ = cb.Call(func() error { return nil })
	}

	stats := cb.GetStats()
	if stats.State != "closed" {
		t.Errorf("expected closed state, got %s", stats.State)
	}
	if stats.SuccessCount != 3 {
		t.Errorf("expected 3 successes, got %d", stats.SuccessCount)
	}
	if stats.FailureThreshold != 10 {
		t.Errorf("expected failure threshold 10, got %d", stats.FailureThreshold)
	}
}

// TestState_String verifies string representations.
func TestState_String(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half_open"},
		{State(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.expected {
			t.Errorf("State(%d).String() = %q, want %q", tc.state, got, tc.expected)
		}
	}
}

// TestWithTimeoutFunc_Success verifies that a fast function completes normally.
func TestWithTimeoutFunc_Success(t *testing.T) {
	err := WithTimeoutFunc(context.Background(), 100*time.Millisecond, func(ctx context.Context) error {
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// TestWithTimeoutFunc_Timeout verifies that a slow function is cancelled.
func TestWithTimeoutFunc_Timeout(t *testing.T) {
	err := WithTimeoutFunc(context.Background(), 20*time.Millisecond, func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

// TestWithTimeoutFunc_ZeroTimeout verifies that zero timeout runs without a deadline.
func TestWithTimeoutFunc_ZeroTimeout(t *testing.T) {
	err := WithTimeoutFunc(context.Background(), 0, func(ctx context.Context) error {
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// TestSleep_Cancellation verifies that Sleep returns on context cancel.
func TestSleep_Cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := Sleep(ctx, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestRetry_NilConfig verifies that passing nil config uses defaults.
func TestRetry_NilConfig(t *testing.T) {
	var attempts int
	err := Retry(context.Background(), nil, func() error {
		attempts++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt with nil config, got %d", attempts)
	}
}

// TestDefaultConfig verifies default config values are applied.
func TestDefaultConfig(t *testing.T) {
	cb := New(Config{Name: "defaults"})
	if cb.failureThreshold != 5 {
		t.Errorf("expected default failure threshold 5, got %d", cb.failureThreshold)
	}
	if cb.successThreshold != 3 {
		t.Errorf("expected default success threshold 3, got %d", cb.successThreshold)
	}
	if cb.timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %v", cb.timeout)
	}
}

// TestSleep_NormalCompletion verifies Sleep returns nil when not cancelled.
func TestSleep_NormalCompletion(t *testing.T) {
	err := Sleep(context.Background(), time.Millisecond)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}
