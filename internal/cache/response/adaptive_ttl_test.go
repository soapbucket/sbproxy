package responsecache

import (
	"testing"
	"time"
)

func TestAdaptiveTTL_StableContent(t *testing.T) {
	a := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:        true,
		MinTTL:         10 * time.Second,
		MaxTTL:         24 * time.Hour,
		SampleWindow:   10,
		StabilityBonus: 1.5,
	})

	base := time.Now().Add(-10 * time.Hour)

	// Record changes at very regular, long intervals (1 hour apart)
	for i := 0; i < 5; i++ {
		a.RecordChange("stable-key", base.Add(time.Duration(i)*time.Hour))
	}

	ttl := a.GetTTL("stable-key", 5*time.Minute)

	// Stable content with 1-hour intervals should get a high TTL
	// Median interval = 1h, stability bonus = 1.5, so TTL should be 1.5h
	if ttl < 30*time.Minute {
		t.Errorf("expected stable content to have high TTL, got %v", ttl)
	}
	if ttl > 24*time.Hour {
		t.Errorf("expected TTL to be clamped to max, got %v", ttl)
	}
}

func TestAdaptiveTTL_FrequentChanges(t *testing.T) {
	a := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:        true,
		MinTTL:         5 * time.Second,
		MaxTTL:         1 * time.Hour,
		SampleWindow:   10,
		StabilityBonus: 1.5,
	})

	base := time.Now().Add(-time.Minute)

	// Record changes every 2 seconds (very frequent)
	for i := 0; i < 8; i++ {
		a.RecordChange("hot-key", base.Add(time.Duration(i)*2*time.Second))
	}

	ttl := a.GetTTL("hot-key", 5*time.Minute)

	// Frequent changes (2s intervals) should produce a low TTL
	// Median interval = 2s, frequent changes -> interval/2 = 1s, clamped to min 5s
	if ttl > 30*time.Second {
		t.Errorf("expected frequently changing content to have low TTL, got %v", ttl)
	}
	if ttl < 5*time.Second {
		t.Errorf("expected TTL to be at least MinTTL, got %v", ttl)
	}
}

func TestAdaptiveTTL_Clamping(t *testing.T) {
	minTTL := 30 * time.Second
	maxTTL := 10 * time.Minute
	a := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:        true,
		MinTTL:         minTTL,
		MaxTTL:         maxTTL,
		SampleWindow:   10,
		StabilityBonus: 1.5,
	})

	// Test min clamping: very frequent changes
	base := time.Now()
	for i := 0; i < 5; i++ {
		a.RecordChange("fast-key", base.Add(time.Duration(i)*time.Millisecond*100))
	}
	ttl := a.GetTTL("fast-key", time.Minute)
	if ttl < minTTL {
		t.Errorf("expected TTL >= MinTTL (%v), got %v", minTTL, ttl)
	}

	// Test max clamping: very stable content with high default
	// No changes recorded for this key, so default * stability_bonus is used
	ttl = a.GetTTL("nonexistent-key", 24*time.Hour)
	if ttl > maxTTL {
		t.Errorf("expected TTL <= MaxTTL (%v), got %v", maxTTL, ttl)
	}
}

func TestAdaptiveTTL_DefaultFallback(t *testing.T) {
	a := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:        true,
		MinTTL:         10 * time.Second,
		MaxTTL:         24 * time.Hour,
		SampleWindow:   10,
		StabilityBonus: 2.0,
	})

	defaultTTL := 5 * time.Minute
	ttl := a.GetTTL("unknown-key", defaultTTL)

	// No data: expected default * stability_bonus = 10 minutes
	expected := time.Duration(float64(defaultTTL) * 2.0)
	if ttl != expected {
		t.Errorf("expected TTL %v for unknown key, got %v", expected, ttl)
	}
}

func TestAdaptiveTTL_Stats(t *testing.T) {
	a := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:      true,
		SampleWindow: 5,
	})

	base := time.Now().Add(-5 * time.Minute)
	for i := 0; i < 3; i++ {
		a.RecordChange("stats-key", base.Add(time.Duration(i)*time.Minute))
	}

	stats := a.Stats()
	s, ok := stats["stats-key"]
	if !ok {
		t.Fatal("expected stats for 'stats-key'")
	}
	if s.SampleCount != 2 {
		t.Errorf("expected 2 samples, got %d", s.SampleCount)
	}
	if s.MedianInterval != time.Minute {
		t.Errorf("expected median interval of 1m, got %v", s.MedianInterval)
	}
}

func TestAdaptiveTTL_SampleWindowTrimming(t *testing.T) {
	window := 3
	a := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:      true,
		SampleWindow: window,
	})

	base := time.Now().Add(-10 * time.Minute)
	// Record 6 changes, but window is only 3
	for i := 0; i < 6; i++ {
		a.RecordChange("trim-key", base.Add(time.Duration(i)*time.Minute))
	}

	stats := a.Stats()
	s := stats["trim-key"]
	if s.SampleCount != window {
		t.Errorf("expected sample count to be trimmed to %d, got %d", window, s.SampleCount)
	}
}

func TestMedianDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    []time.Duration
		expected time.Duration
	}{
		{"empty", nil, 0},
		{"single", []time.Duration{5 * time.Second}, 5 * time.Second},
		{"odd count", []time.Duration{1 * time.Second, 3 * time.Second, 5 * time.Second}, 3 * time.Second},
		{"even count", []time.Duration{1 * time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second}, 2500 * time.Millisecond},
		{"unsorted", []time.Duration{5 * time.Second, 1 * time.Second, 3 * time.Second}, 3 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := medianDuration(tt.input)
			if got != tt.expected {
				t.Errorf("medianDuration(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
