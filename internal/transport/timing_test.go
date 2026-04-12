package transport

import (
	"strings"
	"testing"
	"time"
)

func TestTimingCollector_Header(t *testing.T) {
	tc := NewTimingCollector()
	tc.Record("policy", 45*time.Microsecond)
	tc.Record("auth", 12*time.Microsecond)
	tc.Record("overhead", 57*time.Microsecond)

	got := tc.Header()
	expected := "policy=45µs;auth=12µs;overhead=57µs"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestTimingCollector_Empty(t *testing.T) {
	tc := NewTimingCollector()
	if got := tc.Header(); got != "" {
		t.Fatalf("expected empty string for empty collector, got %q", got)
	}
}

func TestTimingCollector_Overflow(t *testing.T) {
	tc := NewTimingCollector()
	// Fill all 8 slots.
	for i := range maxTimingStages {
		tc.Record("stage", time.Duration(i)*time.Microsecond)
	}
	// The 9th should be silently dropped.
	tc.Record("overflow", time.Millisecond)

	header := tc.Header()
	if strings.Contains(header, "overflow") {
		t.Fatal("overflow stage should have been dropped")
	}
	if tc.count != maxTimingStages {
		t.Fatalf("expected count %d, got %d", maxTimingStages, tc.count)
	}
}

func BenchmarkTimingCollector(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		tc := NewTimingCollector()
		tc.Record("policy", 45*time.Microsecond)
		tc.Record("auth", 12*time.Microsecond)
		tc.Record("proxy", 3*time.Millisecond)
		_ = tc.Header()
	}
}
