package policy

import (
	"testing"
	"time"
)

func TestShouldInjectDelay_Disabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  FaultInjectionConfig
	}{
		{"zero delay", FaultInjectionConfig{DelayMs: 0, DelayPercent: 0.5}},
		{"zero percent", FaultInjectionConfig{DelayMs: 100, DelayPercent: 0}},
		{"negative delay", FaultInjectionConfig{DelayMs: -1, DelayPercent: 0.5}},
		{"negative percent", FaultInjectionConfig{DelayMs: 100, DelayPercent: -0.1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inject, dur := ShouldInjectDelay(tt.cfg)
			if inject {
				t.Error("expected no injection")
			}
			if dur != 0 {
				t.Errorf("expected zero duration, got %v", dur)
			}
		})
	}
}

func TestShouldInjectDelay_Always(t *testing.T) {
	cfg := FaultInjectionConfig{
		DelayMs:      100,
		DelayPercent: 1.0,
	}

	for i := 0; i < 100; i++ {
		inject, dur := ShouldInjectDelay(cfg)
		if !inject {
			t.Fatal("expected injection with 100% rate")
		}
		if dur != 100*time.Millisecond {
			t.Errorf("expected 100ms, got %v", dur)
		}
	}
}

func TestShouldInjectDelay_ClampOver1(t *testing.T) {
	cfg := FaultInjectionConfig{
		DelayMs:      50,
		DelayPercent: 2.0, // should be clamped to 1.0
	}

	for i := 0; i < 100; i++ {
		inject, _ := ShouldInjectDelay(cfg)
		if !inject {
			t.Fatal("expected injection with percent > 1.0 (clamped to 1.0)")
		}
	}
}

func TestShouldInjectAbort_Disabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  FaultInjectionConfig
	}{
		{"zero code", FaultInjectionConfig{AbortCode: 0, AbortPercent: 0.5}},
		{"zero percent", FaultInjectionConfig{AbortCode: 503, AbortPercent: 0}},
		{"negative code", FaultInjectionConfig{AbortCode: -1, AbortPercent: 0.5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inject, code := ShouldInjectAbort(tt.cfg)
			if inject {
				t.Error("expected no injection")
			}
			if code != 0 {
				t.Errorf("expected zero code, got %d", code)
			}
		})
	}
}

func TestShouldInjectAbort_Always(t *testing.T) {
	cfg := FaultInjectionConfig{
		AbortCode:    503,
		AbortPercent: 1.0,
	}

	for i := 0; i < 100; i++ {
		inject, code := ShouldInjectAbort(cfg)
		if !inject {
			t.Fatal("expected injection with 100% rate")
		}
		if code != 503 {
			t.Errorf("expected 503, got %d", code)
		}
	}
}

func TestShouldInjectDelay_Probabilistic(t *testing.T) {
	cfg := FaultInjectionConfig{
		DelayMs:      100,
		DelayPercent: 0.5,
	}

	injected := 0
	runs := 10000
	for i := 0; i < runs; i++ {
		if inject, _ := ShouldInjectDelay(cfg); inject {
			injected++
		}
	}

	// With 50% rate, expect 40-60% range
	lowerBound := runs * 40 / 100
	upperBound := runs * 60 / 100
	if injected < lowerBound || injected > upperBound {
		t.Errorf("expected ~50%% injection rate, got %d/%d (%.1f%%)", injected, runs, float64(injected)/float64(runs)*100)
	}
}

func TestShouldInjectAbort_Probabilistic(t *testing.T) {
	cfg := FaultInjectionConfig{
		AbortCode:    500,
		AbortPercent: 0.3,
	}

	injected := 0
	runs := 10000
	for i := 0; i < runs; i++ {
		if inject, _ := ShouldInjectAbort(cfg); inject {
			injected++
		}
	}

	// With 30% rate, expect 20-40% range
	lowerBound := runs * 20 / 100
	upperBound := runs * 40 / 100
	if injected < lowerBound || injected > upperBound {
		t.Errorf("expected ~30%% injection rate, got %d/%d (%.1f%%)", injected, runs, float64(injected)/float64(runs)*100)
	}
}
