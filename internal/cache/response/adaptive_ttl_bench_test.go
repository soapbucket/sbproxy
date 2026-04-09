package responsecache

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkAdaptiveTTL_GetTTL_Cached(b *testing.B) {
	b.ReportAllocs()
	at := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:      true,
		MinTTL:       10 * time.Second,
		MaxTTL:       24 * time.Hour,
		SampleWindow: 10,
	})
	// Pre-populate with change data so GetTTL hits the cached currentTTL path.
	now := time.Now()
	for i := 0; i < 10; i++ {
		at.RecordChange("test-key", now.Add(time.Duration(i)*5*time.Minute))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		at.GetTTL("test-key", 5*time.Minute)
	}
}

func BenchmarkAdaptiveTTL_GetTTL_Miss(b *testing.B) {
	b.ReportAllocs()
	at := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:      true,
		MinTTL:       10 * time.Second,
		MaxTTL:       24 * time.Hour,
		SampleWindow: 10,
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		at.GetTTL("unknown-key", 5*time.Minute)
	}
}

func BenchmarkAdaptiveTTL_RecordChange(b *testing.B) {
	b.ReportAllocs()
	at := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:      true,
		SampleWindow: 10,
	})
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		at.RecordChange(fmt.Sprintf("key-%d", i%100), now.Add(time.Duration(i)*time.Second))
	}
}

func BenchmarkAdaptiveTTL_Stats(b *testing.B) {
	b.ReportAllocs()
	at := NewAdaptiveTTL(AdaptiveTTLConfig{
		Enabled:      true,
		SampleWindow: 10,
	})
	now := time.Now()
	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("key-%d", i)
		for j := 0; j < 5; j++ {
			at.RecordChange(key, now.Add(time.Duration(j)*time.Minute))
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		at.Stats()
	}
}
