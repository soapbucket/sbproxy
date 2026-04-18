package transport

import (
	"testing"
	"time"
)

func TestNewAutoTuner_Defaults(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{})
	if at.config.MinConnections != defaultMinConnections {
		t.Errorf("expected min=%d, got %d", defaultMinConnections, at.config.MinConnections)
	}
	if at.config.MaxConnections != defaultMaxConnections {
		t.Errorf("expected max=%d, got %d", defaultMaxConnections, at.config.MaxConnections)
	}
	if at.config.TargetLatencyMs != defaultTargetLatency {
		t.Errorf("expected target=%d, got %d", defaultTargetLatency, at.config.TargetLatencyMs)
	}
	if at.CurrentSize() != defaultMinConnections {
		t.Errorf("expected initial size=%d, got %d", defaultMinConnections, at.CurrentSize())
	}
}

func TestNewAutoTuner_MaxClamped(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{MinConnections: 50, MaxConnections: 10})
	if at.config.MaxConnections != 50 {
		t.Errorf("expected max clamped to min=50, got %d", at.config.MaxConnections)
	}
}

func TestAutoTuner_NoSamplesReturnsCurrent(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{MinConnections: 20, AdjustInterval: 0})
	// Force past adjust interval
	at.lastAdjust = time.Now().Add(-1 * time.Hour)

	size := at.SuggestedSize()
	if size != 20 {
		t.Errorf("expected 20 with no samples, got %d", size)
	}
}

func TestAutoTuner_GrowsOnHighLatency(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{
		MinConnections:  10,
		MaxConnections:  100,
		TargetLatencyMs: 50,
		AdjustInterval:  1 * time.Millisecond,
	})
	at.lastAdjust = time.Now().Add(-1 * time.Hour)

	// Record high latency samples
	for i := 0; i < 10; i++ {
		at.RecordLatency(200.0)
	}

	size := at.SuggestedSize()
	if size <= 10 {
		t.Errorf("expected pool to grow beyond 10, got %d", size)
	}
}

func TestAutoTuner_ShrinksOnLowLatency(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{
		MinConnections:  5,
		MaxConnections:  100,
		TargetLatencyMs: 100,
		AdjustInterval:  1 * time.Millisecond,
	})
	// Start with a large current size
	at.currentSize = 50
	at.lastAdjust = time.Now().Add(-1 * time.Hour)

	// Record very low latency samples (well below shrinkThreshold)
	for i := 0; i < 10; i++ {
		at.RecordLatency(5.0)
	}

	size := at.SuggestedSize()
	if size >= 50 {
		t.Errorf("expected pool to shrink below 50, got %d", size)
	}
}

func TestAutoTuner_RespectsMinBound(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{
		MinConnections:  20,
		MaxConnections:  100,
		TargetLatencyMs: 100,
		AdjustInterval:  1 * time.Millisecond,
	})
	at.currentSize = 21
	at.lastAdjust = time.Now().Add(-1 * time.Hour)

	// Very low latency should shrink but not below min
	for i := 0; i < 10; i++ {
		at.RecordLatency(1.0)
	}

	size := at.SuggestedSize()
	if size < 20 {
		t.Errorf("expected size >= min 20, got %d", size)
	}
}

func TestAutoTuner_RespectsMaxBound(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{
		MinConnections:  10,
		MaxConnections:  15,
		TargetLatencyMs: 50,
		AdjustInterval:  1 * time.Millisecond,
	})
	at.currentSize = 14
	at.lastAdjust = time.Now().Add(-1 * time.Hour)

	// High latency should grow but not beyond max
	for i := 0; i < 10; i++ {
		at.RecordLatency(500.0)
	}

	size := at.SuggestedSize()
	if size > 15 {
		t.Errorf("expected size <= max 15, got %d", size)
	}
}

func TestAutoTuner_SkipsAdjustmentBeforeInterval(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{
		MinConnections:  10,
		MaxConnections:  100,
		TargetLatencyMs: 50,
		AdjustInterval:  1 * time.Hour, // very long interval
	})

	for i := 0; i < 10; i++ {
		at.RecordLatency(500.0)
	}

	// Should not adjust because interval hasn't elapsed
	size := at.SuggestedSize()
	if size != 10 {
		t.Errorf("expected no adjustment before interval, got %d", size)
	}
}

func TestAutoTuner_SampleEviction(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{})

	// Add more than maxSamples
	for i := 0; i < maxSamples+500; i++ {
		at.RecordLatency(float64(i))
	}

	at.mu.Lock()
	count := len(at.latencySamples)
	at.mu.Unlock()

	if count > maxSamples {
		t.Errorf("expected at most %d samples, got %d", maxSamples, count)
	}
}

func TestAutoTuner_ClearsSamplesAfterAdjust(t *testing.T) {
	at := NewAutoTuner(AutoTuneConfig{
		AdjustInterval: 1 * time.Millisecond,
	})
	at.lastAdjust = time.Now().Add(-1 * time.Hour)

	at.RecordLatency(50.0)
	at.SuggestedSize()

	at.mu.Lock()
	count := len(at.latencySamples)
	at.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 samples after adjustment, got %d", count)
	}
}
