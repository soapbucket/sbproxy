// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	slidingWindowSize = 1000
	// Circuit-breaker thresholds. Tuned so transient connection churn
	// (idle-pool cycling, momentary upstream hiccups) does not trip the
	// breaker and take a provider out of rotation for an extended
	// window. The previous defaults (5 consecutive failures, 30s open)
	// were too aggressive for gateway workloads where concurrent
	// requests to the same host can briefly exhaust ephemeral ports or
	// produce a cluster of 1-2ms dial failures under load. See the
	// regression analysis in docs/competitors/LOCAL_SMOKE_RESULTS.md.
	circuitOpenDuration  = 10 * time.Second
	circuitFailThreshold = 50
	circuitHalfOpenMax   = 5
)

// ProviderTracker maintains real-time health and performance data per provider.
type ProviderTracker struct {
	stats map[string]*ProviderStats
	mu    sync.RWMutex
}

// ProviderStats holds per-provider health metrics.
type ProviderStats struct {
	// Latency tracking (sliding window)
	latencies *slidingWindow

	// Request counters
	totalRequests atomic.Int64
	totalErrors   atomic.Int64

	// Token tracking
	tokensConsumed atomic.Int64
	lastTokenReset atomic.Int64

	// In-flight tracking
	inFlight atomic.Int64

	// Circuit breaker
	cb *circuitBreaker
}

// NewProviderTracker creates a new provider tracker.
func NewProviderTracker() *ProviderTracker {
	return &ProviderTracker{
		stats: make(map[string]*ProviderStats),
	}
}

func (pt *ProviderTracker) getOrCreate(name string) *ProviderStats {
	pt.mu.RLock()
	s, ok := pt.stats[name]
	pt.mu.RUnlock()
	if ok {
		return s
	}

	pt.mu.Lock()
	defer pt.mu.Unlock()
	if s, ok = pt.stats[name]; ok {
		return s
	}
	s = &ProviderStats{
		latencies: newSlidingWindow(slidingWindowSize),
		cb:        newCircuitBreaker(circuitFailThreshold, circuitOpenDuration, circuitHalfOpenMax),
	}
	s.lastTokenReset.Store(time.Now().Unix())
	pt.stats[name] = s
	return s
}

// RecordSuccess records a successful request with its latency.
func (pt *ProviderTracker) RecordSuccess(name string, latency time.Duration) {
	s := pt.getOrCreate(name)
	s.totalRequests.Add(1)
	s.latencies.Add(latency.Microseconds())
	s.cb.RecordSuccess()
}

// RecordError records a failed request.
func (pt *ProviderTracker) RecordError(name string) {
	s := pt.getOrCreate(name)
	s.totalRequests.Add(1)
	s.totalErrors.Add(1)
	s.cb.RecordFailure()
}

// RecordTokens records token consumption for a provider.
func (pt *ProviderTracker) RecordTokens(name string, tokens int64) {
	s := pt.getOrCreate(name)
	// Reset counter if a minute has passed
	now := time.Now().Unix()
	lastReset := s.lastTokenReset.Load()
	if now-lastReset >= 60 {
		if s.lastTokenReset.CompareAndSwap(lastReset, now) {
			s.tokensConsumed.Store(0)
		}
	}
	s.tokensConsumed.Add(tokens)
}

// IncrInFlight increments the in-flight counter.
func (pt *ProviderTracker) IncrInFlight(name string) {
	s := pt.getOrCreate(name)
	s.inFlight.Add(1)
}

// DecrInFlight decrements the in-flight counter.
func (pt *ProviderTracker) DecrInFlight(name string) {
	s := pt.getOrCreate(name)
	s.inFlight.Add(-1)
}

// P50Latency returns the p50 latency in microseconds for a provider.
func (pt *ProviderTracker) P50Latency(name string) int64 {
	pt.mu.RLock()
	s, ok := pt.stats[name]
	pt.mu.RUnlock()
	if !ok {
		return 0
	}
	return s.latencies.Percentile(50)
}

// P95Latency returns the p95 latency in microseconds.
func (pt *ProviderTracker) P95Latency(name string) int64 {
	pt.mu.RLock()
	s, ok := pt.stats[name]
	pt.mu.RUnlock()
	if !ok {
		return 0
	}
	return s.latencies.Percentile(95)
}

// InFlight returns the number of in-flight requests for a provider.
func (pt *ProviderTracker) InFlight(name string) int64 {
	pt.mu.RLock()
	s, ok := pt.stats[name]
	pt.mu.RUnlock()
	if !ok {
		return 0
	}
	return s.inFlight.Load()
}

// TokensConsumed returns tokens consumed in the current minute.
func (pt *ProviderTracker) TokensConsumed(name string) int64 {
	pt.mu.RLock()
	s, ok := pt.stats[name]
	pt.mu.RUnlock()
	if !ok {
		return 0
	}
	// Reset if a minute has passed
	now := time.Now().Unix()
	lastReset := s.lastTokenReset.Load()
	if now-lastReset >= 60 {
		return 0
	}
	return s.tokensConsumed.Load()
}

// ErrorRate returns the error rate (0.0 to 1.0) for a provider.
func (pt *ProviderTracker) ErrorRate(name string) float64 {
	pt.mu.RLock()
	s, ok := pt.stats[name]
	pt.mu.RUnlock()
	if !ok {
		return 0
	}
	total := s.totalRequests.Load()
	if total == 0 {
		return 0
	}
	return float64(s.totalErrors.Load()) / float64(total)
}

// IsCircuitOpen returns true if the circuit breaker is open for a provider.
func (pt *ProviderTracker) IsCircuitOpen(name string) bool {
	pt.mu.RLock()
	s, ok := pt.stats[name]
	pt.mu.RUnlock()
	if !ok {
		return false
	}
	return s.cb.IsOpen()
}

// CircuitState returns circuit breaker state for a provider.
func (pt *ProviderTracker) CircuitState(name string) string {
	pt.mu.RLock()
	s, ok := pt.stats[name]
	pt.mu.RUnlock()
	if !ok {
		return "closed"
	}
	return s.cb.State()
}

// slidingWindow is a fixed-size ring buffer for latency tracking.
type slidingWindow struct {
	values []int64
	pos    int
	count  int
	mu     sync.Mutex
}

func newSlidingWindow(size int) *slidingWindow {
	return &slidingWindow{
		values: make([]int64, size),
	}
}

// Add performs the add operation on the slidingWindow.
func (sw *slidingWindow) Add(value int64) {
	sw.mu.Lock()
	sw.values[sw.pos] = value
	sw.pos = (sw.pos + 1) % len(sw.values)
	if sw.count < len(sw.values) {
		sw.count++
	}
	sw.mu.Unlock()
}

// Percentile returns the approximate percentile value (0-100).
func (sw *slidingWindow) Percentile(pct int) int64 {
	sw.mu.Lock()
	if sw.count == 0 {
		sw.mu.Unlock()
		return 0
	}

	// Copy valid entries for sorting
	n := sw.count
	tmp := make([]int64, n)
	if n == len(sw.values) {
		copy(tmp, sw.values)
	} else {
		copy(tmp, sw.values[:n])
	}
	sw.mu.Unlock()

	// Sort using O(n log n) quicksort
	sort.Slice(tmp[:n], func(i, j int) bool { return tmp[i] < tmp[j] })

	idx := (pct * (n - 1)) / 100
	return tmp[idx]
}

// circuitBreaker implements a simple circuit breaker.
type circuitBreaker struct {
	failThreshold int
	openDuration  time.Duration
	halfOpenMax   int

	failures      atomic.Int64
	state         atomic.Int32 // 0=closed, 1=open, 2=half-open
	openedAt      atomic.Int64 // unix nano
	halfOpenCount atomic.Int64
}

const (
	cbClosed   int32 = 0
	cbOpen     int32 = 1
	cbHalfOpen int32 = 2
)

func newCircuitBreaker(failThreshold int, openDuration time.Duration, halfOpenMax int) *circuitBreaker {
	return &circuitBreaker{
		failThreshold: failThreshold,
		openDuration:  openDuration,
		halfOpenMax:   halfOpenMax,
	}
}

// IsOpen reports whether the circuitBreaker is open.
func (cb *circuitBreaker) IsOpen() bool {
	state := cb.state.Load()
	if state == cbClosed {
		return false
	}
	if state == cbOpen {
		// Check if timeout has elapsed
		openedAt := cb.openedAt.Load()
		if time.Now().UnixNano()-openedAt > cb.openDuration.Nanoseconds() {
			// Transition to half-open
			cb.state.Store(cbHalfOpen)
			cb.halfOpenCount.Store(0)
			return false
		}
		return true
	}
	// Half-open: allow limited requests
	return cb.halfOpenCount.Load() >= int64(cb.halfOpenMax)
}

// RecordSuccess performs the record success operation on the circuitBreaker.
func (cb *circuitBreaker) RecordSuccess() {
	state := cb.state.Load()
	if state == cbHalfOpen {
		cb.halfOpenCount.Add(1)
		// After enough successes in half-open, close the circuit
		if cb.halfOpenCount.Load() >= int64(cb.halfOpenMax) {
			cb.state.Store(cbClosed)
			cb.failures.Store(0)
		}
		return
	}
	cb.failures.Store(0)
}

// RecordFailure performs the record failure operation on the circuitBreaker.
func (cb *circuitBreaker) RecordFailure() {
	state := cb.state.Load()
	if state == cbHalfOpen {
		// Failure in half-open → back to open
		cb.state.Store(cbOpen)
		cb.openedAt.Store(time.Now().UnixNano())
		return
	}

	count := cb.failures.Add(1)
	if count >= int64(cb.failThreshold) {
		cb.state.Store(cbOpen)
		cb.openedAt.Store(time.Now().UnixNano())
	}
}

// State performs the state operation on the circuitBreaker.
func (cb *circuitBreaker) State() string {
	switch cb.state.Load() {
	case cbOpen:
		return "open"
	case cbHalfOpen:
		return "half_open"
	default:
		return "closed"
	}
}

// Reset restores the circuitBreaker to its initial state.
func (cb *circuitBreaker) Reset() {
	cb.state.Store(cbClosed)
	cb.failures.Store(0)
	cb.halfOpenCount.Store(0)
}
