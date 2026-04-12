// Package metrics provides AI gateway operational metrics.
package metrics

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// RecoveryStrategy identifies how a failed request was recovered.
type RecoveryStrategy string

const (
	// StrategyFallback indicates the request was routed to a fallback provider.
	StrategyFallback RecoveryStrategy = "fallback"
	// StrategyRetry indicates the request succeeded on a retry attempt.
	StrategyRetry RecoveryStrategy = "retry"
	// StrategyCircuitBreaker indicates the circuit breaker redirected the request.
	StrategyCircuitBreaker RecoveryStrategy = "circuit_breaker"
	// StrategyCache indicates a cached response was served.
	StrategyCache RecoveryStrategy = "cache"
	// StrategySWR indicates stale-while-revalidate served a stale response.
	StrategySWR RecoveryStrategy = "swr"
	// StrategyDegradedMode indicates a degraded-mode response was returned.
	StrategyDegradedMode RecoveryStrategy = "degraded_mode"
)

// allStrategies is the canonical ordering for iteration.
var allStrategies = []RecoveryStrategy{
	StrategyFallback,
	StrategyRetry,
	StrategyCircuitBreaker,
	StrategyCache,
	StrategySWR,
	StrategyDegradedMode,
}

// RecoveredMetrics tracks recovered request counts by strategy.
// All counter operations are lock-free via atomic integers.
// The mutex is only held during snapshot and reset operations.
type RecoveredMetrics struct {
	counters map[RecoveryStrategy]*atomic.Int64
	total    *atomic.Int64
	mu       sync.RWMutex // protects snapshot/reset only
}

// NewRecoveredMetrics creates a new RecoveredMetrics instance with
// pre-initialized counters for every known strategy.
func NewRecoveredMetrics() *RecoveredMetrics {
	m := &RecoveredMetrics{
		counters: make(map[RecoveryStrategy]*atomic.Int64, len(allStrategies)),
		total:    &atomic.Int64{},
	}
	for _, s := range allStrategies {
		m.counters[s] = &atomic.Int64{}
	}
	return m
}

// Record increments the counter for the given recovery strategy.
func (m *RecoveredMetrics) Record(strategy RecoveryStrategy) {
	if c, ok := m.counters[strategy]; ok {
		c.Add(1)
		m.total.Add(1)
	}
}

// Total returns the total number of recovered requests across all strategies.
func (m *RecoveredMetrics) Total() int64 {
	return m.total.Load()
}

// ByStrategy returns the count for a specific recovery strategy.
func (m *RecoveredMetrics) ByStrategy(strategy RecoveryStrategy) int64 {
	if c, ok := m.counters[strategy]; ok {
		return c.Load()
	}
	return 0
}

// Snapshot returns a point-in-time copy of all strategy counters.
func (m *RecoveredMetrics) Snapshot() map[RecoveryStrategy]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snap := make(map[RecoveryStrategy]int64, len(allStrategies))
	for _, s := range allStrategies {
		snap[s] = m.counters[s].Load()
	}
	return snap
}

// Reset zeros all counters.
func (m *RecoveredMetrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, s := range allStrategies {
		m.counters[s].Store(0)
	}
	m.total.Store(0)
}

// PrometheusMetrics returns all counters in Prometheus exposition format.
func (m *RecoveredMetrics) PrometheusMetrics() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder
	b.WriteString("# HELP ai_gateway_recovered_requests_total Total recovered requests\n")
	b.WriteString("# TYPE ai_gateway_recovered_requests_total counter\n")

	for _, s := range allStrategies {
		val := m.counters[s].Load()
		fmt.Fprintf(&b, "ai_gateway_recovered_requests_total{strategy=%q} %d\n", string(s), val)
	}

	return b.String()
}
