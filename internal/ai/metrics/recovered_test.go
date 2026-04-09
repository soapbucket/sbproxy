package metrics

import (
	"strings"
	"sync"
	"testing"
)

func TestRecoveredMetrics_IncrementPerStrategy(t *testing.T) {
	tests := []struct {
		name     string
		strategy RecoveryStrategy
	}{
		{name: "fallback", strategy: StrategyFallback},
		{name: "retry", strategy: StrategyRetry},
		{name: "circuit_breaker", strategy: StrategyCircuitBreaker},
		{name: "cache", strategy: StrategyCache},
		{name: "swr", strategy: StrategySWR},
		{name: "degraded_mode", strategy: StrategyDegradedMode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewRecoveredMetrics()

			m.Record(tt.strategy)
			m.Record(tt.strategy)
			m.Record(tt.strategy)

			got := m.ByStrategy(tt.strategy)
			if got != 3 {
				t.Errorf("ByStrategy(%s) = %d, want 3", tt.strategy, got)
			}

			// Other strategies should be zero.
			for _, other := range allStrategies {
				if other != tt.strategy {
					if v := m.ByStrategy(other); v != 0 {
						t.Errorf("ByStrategy(%s) = %d, want 0", other, v)
					}
				}
			}
		})
	}
}

func TestRecoveredMetrics_Total(t *testing.T) {
	m := NewRecoveredMetrics()

	m.Record(StrategyFallback)
	m.Record(StrategyFallback)
	m.Record(StrategyRetry)
	m.Record(StrategyCache)
	m.Record(StrategySWR)

	// fallback(2) + retry(1) + cache(1) + swr(1) = 5
	if got := m.Total(); got != 5 {
		t.Errorf("Total() = %d, want 5", got)
	}
}

func TestRecoveredMetrics_Snapshot(t *testing.T) {
	m := NewRecoveredMetrics()

	m.Record(StrategyFallback)
	m.Record(StrategyFallback)
	m.Record(StrategyRetry)
	m.Record(StrategyCircuitBreaker)

	snap := m.Snapshot()
	if len(snap) != len(allStrategies) {
		t.Errorf("Snapshot has %d entries, want %d", len(snap), len(allStrategies))
	}
	if snap[StrategyFallback] != 2 {
		t.Errorf("snap[fallback] = %d, want 2", snap[StrategyFallback])
	}
	if snap[StrategyRetry] != 1 {
		t.Errorf("snap[retry] = %d, want 1", snap[StrategyRetry])
	}
	if snap[StrategyCircuitBreaker] != 1 {
		t.Errorf("snap[circuit_breaker] = %d, want 1", snap[StrategyCircuitBreaker])
	}
	if snap[StrategyCache] != 0 {
		t.Errorf("snap[cache] = %d, want 0", snap[StrategyCache])
	}
}

func TestRecoveredMetrics_Reset(t *testing.T) {
	m := NewRecoveredMetrics()

	m.Record(StrategyFallback)
	m.Record(StrategyRetry)
	m.Record(StrategyCache)

	if m.Total() != 3 {
		t.Fatalf("pre-reset Total() = %d, want 3", m.Total())
	}

	m.Reset()

	if got := m.Total(); got != 0 {
		t.Errorf("post-reset Total() = %d, want 0", got)
	}
	for _, s := range allStrategies {
		if v := m.ByStrategy(s); v != 0 {
			t.Errorf("post-reset ByStrategy(%s) = %d, want 0", s, v)
		}
	}
}

func TestRecoveredMetrics_PrometheusFormat(t *testing.T) {
	m := NewRecoveredMetrics()

	for i := 0; i < 43; i++ {
		m.Record(StrategyFallback)
	}
	m.Record(StrategyRetry)

	output := m.PrometheusMetrics()

	// Check HELP and TYPE headers.
	if !strings.Contains(output, "# HELP ai_gateway_recovered_requests_total") {
		t.Error("missing HELP line")
	}
	if !strings.Contains(output, "# TYPE ai_gateway_recovered_requests_total counter") {
		t.Error("missing TYPE line")
	}

	// Check all strategies appear.
	for _, s := range allStrategies {
		label := `strategy="` + string(s) + `"`
		if !strings.Contains(output, label) {
			t.Errorf("missing strategy label %q", s)
		}
	}

	// Verify specific values.
	if !strings.Contains(output, `strategy="fallback"} 43`) {
		t.Errorf("expected fallback=43 in output, got:\n%s", output)
	}
	if !strings.Contains(output, `strategy="retry"} 1`) {
		t.Errorf("expected retry=1 in output, got:\n%s", output)
	}
}

func TestRecoveredMetrics_ConcurrentIncrements(t *testing.T) {
	m := NewRecoveredMetrics()
	const goroutines = 100
	const increments = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		strategy := allStrategies[i%len(allStrategies)]
		go func(s RecoveryStrategy) {
			defer wg.Done()
			for j := 0; j < increments; j++ {
				m.Record(s)
			}
		}(strategy)
	}

	wg.Wait()

	// Total should be goroutines * increments.
	expectedTotal := int64(goroutines * increments)
	if got := m.Total(); got != expectedTotal {
		t.Errorf("Total() = %d, want %d", got, expectedTotal)
	}

	// Verify snapshot sums to total.
	snap := m.Snapshot()
	var sum int64
	for _, v := range snap {
		sum += v
	}
	if sum != expectedTotal {
		t.Errorf("Snapshot sum = %d, want %d", sum, expectedTotal)
	}
}

func TestRecoveredMetrics_UnknownStrategy(t *testing.T) {
	m := NewRecoveredMetrics()

	// Recording an unknown strategy should be a no-op.
	m.Record(RecoveryStrategy("unknown"))

	if got := m.Total(); got != 0 {
		t.Errorf("Total() after unknown strategy = %d, want 0", got)
	}
	if got := m.ByStrategy(RecoveryStrategy("unknown")); got != 0 {
		t.Errorf("ByStrategy(unknown) = %d, want 0", got)
	}
}
