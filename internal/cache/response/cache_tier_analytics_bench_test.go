package responsecache

import "testing"

func BenchmarkCacheTierAnalytics_RecordHit(b *testing.B) {
	b.ReportAllocs()
	cta := NewCacheTierAnalytics()
	// Pre-create the tier to benchmark the steady-state path.
	cta.RecordHit("l1", "origin-1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cta.RecordHit("l1", "origin-1")
	}
}

func BenchmarkCacheTierAnalytics_RecordMiss(b *testing.B) {
	b.ReportAllocs()
	cta := NewCacheTierAnalytics()
	cta.RecordMiss("l1", "origin-1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cta.RecordMiss("l1", "origin-1")
	}
}

func BenchmarkCacheTierAnalytics_HitRate(b *testing.B) {
	b.ReportAllocs()
	cta := NewCacheTierAnalytics()
	for i := 0; i < 1000; i++ {
		cta.RecordHit("l1", "origin-1")
		if i%3 == 0 {
			cta.RecordMiss("l1", "origin-1")
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cta.HitRate("l1")
	}
}

func BenchmarkCacheTierAnalytics_Stats(b *testing.B) {
	b.ReportAllocs()
	cta := NewCacheTierAnalytics()
	tiers := []string{"l1", "l2", "l3"}
	for _, tier := range tiers {
		for i := 0; i < 500; i++ {
			cta.RecordHit(tier, "origin-1")
			if i%4 == 0 {
				cta.RecordMiss(tier, "origin-1")
			}
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cta.Stats()
	}
}
