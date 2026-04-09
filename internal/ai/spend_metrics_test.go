package ai

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSpendMetrics_NoOpDoesNotPanic(t *testing.T) {
	// Reset to defaults to ensure no-ops are in place.
	RegisterSpendMetrics(nil, nil, nil, nil)

	// Calling with arbitrary values must not panic.
	emitSpendMetrics("openai", "gpt-4", "ws-1", "200", 100, 50, 0.003, false, "")
	emitSpendMetrics("anthropic", "claude-3-opus", "ws-2", "200", 0, 0, 0, true, "semantic")
}

func TestSpendMetrics_CustomCallbacksInvoked(t *testing.T) {
	var reqCount atomic.Int64
	var tokenSum atomic.Int64
	var costSum atomic.Int64
	var cacheCount atomic.Int64

	RegisterSpendMetrics(
		func(_, _, _, _ string) { reqCount.Add(1) },
		func(_, _ string, count int) { tokenSum.Add(int64(count)) },
		func(_, _, _ string, cost float64) { costSum.Add(int64(cost * 1_000_000)) },
		func(_, _ string) { cacheCount.Add(1) },
	)

	emitSpendMetrics("openai", "gpt-4", "ws-1", "200", 100, 50, 0.005, true, "semantic")

	assert.Equal(t, int64(1), reqCount.Load(), "requests callback should fire once")
	assert.Equal(t, int64(150), tokenSum.Load(), "token callback should sum input+output")
	assert.Equal(t, int64(5000), costSum.Load(), "cost callback should fire with microdollars")
	assert.Equal(t, int64(1), cacheCount.Load(), "cache hit callback should fire")
}

func TestSpendMetrics_NoCostDoesNotFireCostCallback(t *testing.T) {
	var costFired atomic.Int64

	RegisterSpendMetrics(
		func(_, _, _, _ string) {},
		func(_, _ string, _ int) {},
		func(_, _, _ string, _ float64) { costFired.Add(1) },
		func(_, _ string) {},
	)

	emitSpendMetrics("openai", "gpt-4", "ws-1", "200", 10, 5, 0, false, "")

	assert.Equal(t, int64(0), costFired.Load(), "cost callback should not fire when cost is zero")
}

func TestSpendMetrics_NoCacheHitDoesNotFireCacheCallback(t *testing.T) {
	var cacheFired atomic.Int64

	RegisterSpendMetrics(
		func(_, _, _, _ string) {},
		func(_, _ string, _ int) {},
		func(_, _, _ string, _ float64) {},
		func(_, _ string) { cacheFired.Add(1) },
	)

	emitSpendMetrics("openai", "gpt-4", "ws-1", "200", 10, 5, 0.001, false, "")

	assert.Equal(t, int64(0), cacheFired.Load(), "cache callback should not fire when cache miss")
}

func TestSpendMetrics_RegisterPartialNils(t *testing.T) {
	// Register only the requests callback, others nil (should keep previous).
	var called atomic.Int64
	RegisterSpendMetrics(
		func(_, _, _, _ string) { called.Add(1) },
		nil, nil, nil,
	)

	// Should not panic.
	emitSpendMetrics("openai", "gpt-4", "ws-1", "200", 10, 5, 0.001, true, "semantic")
	assert.Equal(t, int64(1), called.Load())
}
