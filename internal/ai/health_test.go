package ai

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestProviderTracker_RecordSuccess(t *testing.T) {
	pt := NewProviderTracker()

	pt.RecordSuccess("test", 100_000)
	pt.RecordSuccess("test", 200_000)
	pt.RecordSuccess("test", 300_000)

	assert.Equal(t, float64(0), pt.ErrorRate("test"))
}

func TestProviderTracker_RecordError(t *testing.T) {
	pt := NewProviderTracker()

	pt.RecordSuccess("test", 100_000)
	pt.RecordError("test")

	assert.InDelta(t, 0.5, pt.ErrorRate("test"), 0.01)
}

func TestProviderTracker_P50Latency(t *testing.T) {
	pt := NewProviderTracker()

	// Add latencies in microseconds
	for i := 1; i <= 100; i++ {
		pt.RecordSuccess("test", time.Duration(i)*time.Millisecond)
	}

	p50 := pt.P50Latency("test")
	// p50 should be around 50_000 (50ms in microseconds)
	assert.InDelta(t, 50_000, p50, 5_000)
}

func TestProviderTracker_P95Latency(t *testing.T) {
	pt := NewProviderTracker()

	for i := 1; i <= 100; i++ {
		pt.RecordSuccess("test", time.Duration(i)*time.Millisecond)
	}

	p95 := pt.P95Latency("test")
	assert.InDelta(t, 95_000, p95, 5_000)
}

func TestProviderTracker_InFlight(t *testing.T) {
	pt := NewProviderTracker()

	pt.IncrInFlight("test")
	pt.IncrInFlight("test")
	pt.IncrInFlight("test")
	assert.Equal(t, int64(3), pt.InFlight("test"))

	pt.DecrInFlight("test")
	assert.Equal(t, int64(2), pt.InFlight("test"))
}

func TestProviderTracker_TokensConsumed(t *testing.T) {
	pt := NewProviderTracker()

	pt.RecordTokens("test", 100)
	pt.RecordTokens("test", 200)
	assert.Equal(t, int64(300), pt.TokensConsumed("test"))
}

func TestProviderTracker_ConcurrentAccess(t *testing.T) {
	pt := NewProviderTracker()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			pt.RecordSuccess("test", 100_000)
		}()
		go func() {
			defer wg.Done()
			pt.RecordError("test")
		}()
		go func() {
			defer wg.Done()
			pt.P50Latency("test")
			pt.InFlight("test")
			pt.ErrorRate("test")
		}()
	}

	wg.Wait()
	// Just verify no panics or race conditions
}

func TestProviderTracker_UnknownProvider(t *testing.T) {
	pt := NewProviderTracker()

	assert.Equal(t, int64(0), pt.P50Latency("unknown"))
	assert.Equal(t, int64(0), pt.InFlight("unknown"))
	assert.Equal(t, float64(0), pt.ErrorRate("unknown"))
	assert.Equal(t, int64(0), pt.TokensConsumed("unknown"))
	assert.False(t, pt.IsCircuitOpen("unknown"))
}

func TestCircuitBreaker_Lifecycle(t *testing.T) {
	cb := newCircuitBreaker(3, 100*time.Millisecond, 2)

	// Initially closed
	assert.Equal(t, "closed", cb.State())
	assert.False(t, cb.IsOpen())

	// Record failures to trigger open
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, "closed", cb.State())

	cb.RecordFailure() // threshold = 3
	assert.Equal(t, "open", cb.State())
	assert.True(t, cb.IsOpen())

	// Wait for timeout to transition to half-open
	time.Sleep(150 * time.Millisecond)
	assert.False(t, cb.IsOpen()) // Should transition to half-open
	assert.Equal(t, "half_open", cb.State())

	// Success in half-open
	cb.RecordSuccess()
	cb.RecordSuccess() // halfOpenMax = 2 → close
	assert.Equal(t, "closed", cb.State())
	assert.False(t, cb.IsOpen())
}

func TestCircuitBreaker_FailureInHalfOpen(t *testing.T) {
	cb := newCircuitBreaker(2, 50*time.Millisecond, 3)

	// Trigger open
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, "open", cb.State())

	// Wait for half-open
	time.Sleep(60 * time.Millisecond)
	cb.IsOpen() // triggers transition

	assert.Equal(t, "half_open", cb.State())

	// Failure in half-open goes back to open
	cb.RecordFailure()
	assert.Equal(t, "open", cb.State())
}

func TestCircuitBreaker_Reset(t *testing.T) {
	cb := newCircuitBreaker(2, time.Minute, 2)
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, "open", cb.State())

	cb.Reset()
	assert.Equal(t, "closed", cb.State())
	assert.False(t, cb.IsOpen())
}

func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	cb := newCircuitBreaker(3, time.Minute, 2)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // should reset failures

	cb.RecordFailure() // only 1 failure now, not 3
	assert.Equal(t, "closed", cb.State())
}

func TestSlidingWindow_Empty(t *testing.T) {
	sw := newSlidingWindow(100)
	assert.Equal(t, int64(0), sw.Percentile(50))
}

func TestSlidingWindow_SingleValue(t *testing.T) {
	sw := newSlidingWindow(100)
	sw.Add(42)
	assert.Equal(t, int64(42), sw.Percentile(50))
	assert.Equal(t, int64(42), sw.Percentile(99))
}

func TestSlidingWindow_Wraps(t *testing.T) {
	sw := newSlidingWindow(10)

	// Fill and overflow
	for i := 1; i <= 20; i++ {
		sw.Add(int64(i))
	}

	// Should only contain values 11-20
	p50 := sw.Percentile(50)
	assert.True(t, p50 >= 14 && p50 <= 16, "p50 should be ~15, got %d", p50)
}
