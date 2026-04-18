package routing

import (
	"testing"
	"time"
)

func TestNewP2CEWMARouter_Defaults(t *testing.T) {
	r := NewP2CEWMARouter(P2CEWMAConfig{})
	if r.decayNs != float64(defaultDecayNs) {
		t.Errorf("expected default decay %v, got %v", float64(defaultDecayNs), r.decayNs)
	}
}

func TestNewP2CEWMARouter_CustomDecay(t *testing.T) {
	r := NewP2CEWMARouter(P2CEWMAConfig{DecayNs: int64(5 * time.Second)})
	if r.decayNs != float64(5*time.Second) {
		t.Errorf("expected custom decay, got %v", r.decayNs)
	}
}

func TestP2CEWMARouter_SelectEmpty(t *testing.T) {
	r := NewP2CEWMARouter(P2CEWMAConfig{})
	if got := r.Select(nil); got != "" {
		t.Errorf("expected empty string for nil providers, got %q", got)
	}
}

func TestP2CEWMARouter_SelectSingle(t *testing.T) {
	r := NewP2CEWMARouter(P2CEWMAConfig{})
	if got := r.Select([]string{"a"}); got != "a" {
		t.Errorf("expected 'a', got %q", got)
	}
}

func TestP2CEWMARouter_SelectPrefersFaster(t *testing.T) {
	r := NewP2CEWMARouter(P2CEWMAConfig{})

	// Record high latency for "slow"
	for i := 0; i < 20; i++ {
		r.RecordLatency("slow", 500*time.Millisecond)
	}
	// Record low latency for "fast"
	for i := 0; i < 20; i++ {
		r.RecordLatency("fast", 1*time.Millisecond)
	}

	providers := []string{"slow", "fast"}
	fastCount := 0
	runs := 1000
	for i := 0; i < runs; i++ {
		if r.Select(providers) == "fast" {
			fastCount++
		}
	}

	// "fast" should be selected much more often than "slow"
	if fastCount < runs/2 {
		t.Errorf("expected 'fast' to be selected most of the time, got %d/%d", fastCount, runs)
	}
}

func TestP2CEWMARouter_PendingInfluencesScore(t *testing.T) {
	r := NewP2CEWMARouter(P2CEWMAConfig{})

	// Both providers have the same latency
	r.RecordLatency("a", 10*time.Millisecond)
	r.RecordLatency("b", 10*time.Millisecond)

	// Add many pending requests to "a"
	for i := 0; i < 100; i++ {
		r.IncrementPending("a")
	}

	providers := []string{"a", "b"}
	bCount := 0
	runs := 1000
	for i := 0; i < runs; i++ {
		if r.Select(providers) == "b" {
			bCount++
		}
	}

	// "b" should be selected much more often since "a" has many pending
	if bCount < runs/2 {
		t.Errorf("expected 'b' to be preferred due to lower pending, got %d/%d", bCount, runs)
	}
}

func TestP2CEWMARouter_DecrementPending(t *testing.T) {
	r := NewP2CEWMARouter(P2CEWMAConfig{})
	r.IncrementPending("a")
	r.IncrementPending("a")
	r.DecrementPending("a")

	r.mu.RLock()
	pending := r.metrics["a"].pending
	r.mu.RUnlock()

	if pending != 1 {
		t.Errorf("expected pending=1, got %d", pending)
	}
}

func TestP2CEWMARouter_DecrementPendingNeverNegative(t *testing.T) {
	r := NewP2CEWMARouter(P2CEWMAConfig{})
	r.DecrementPending("a")

	r.mu.RLock()
	pending := r.metrics["a"].pending
	r.mu.RUnlock()

	if pending != 0 {
		t.Errorf("expected pending=0, got %d", pending)
	}
}

func TestP2CEWMARouter_UnknownProvidersPreferred(t *testing.T) {
	r := NewP2CEWMARouter(P2CEWMAConfig{})

	// Record high latency for "known"
	for i := 0; i < 20; i++ {
		r.RecordLatency("known", 500*time.Millisecond)
	}

	providers := []string{"known", "unknown"}
	unknownCount := 0
	runs := 1000
	for i := 0; i < runs; i++ {
		if r.Select(providers) == "unknown" {
			unknownCount++
		}
	}

	// "unknown" has score 0, so it should be preferred
	if unknownCount < runs/2 {
		t.Errorf("expected 'unknown' to be preferred, got %d/%d", unknownCount, runs)
	}
}
