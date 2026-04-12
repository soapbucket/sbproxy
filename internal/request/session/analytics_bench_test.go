package session

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkSessionAnalytics_RecordPageView(b *testing.B) {
	b.ReportAllocs()
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:        true,
		TrackPageFlow:  true,
		SessionTimeout: 30 * time.Minute,
		MaxFlowDepth:   100,
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sa.RecordPageView(fmt.Sprintf("session-%d", i%100), "origin-1", "/products", "/")
	}
}

func BenchmarkSessionAnalytics_RecordPageView_NoFlow(b *testing.B) {
	b.ReportAllocs()
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:        true,
		TrackPageFlow:  false,
		SessionTimeout: 30 * time.Minute,
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sa.RecordPageView(fmt.Sprintf("session-%d", i%100), "origin-1", "/products", "/")
	}
}

func BenchmarkSessionAnalytics_Stats(b *testing.B) {
	b.ReportAllocs()
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:        true,
		TrackPageFlow:  true,
		SessionTimeout: 30 * time.Minute,
	})
	// Pre-populate with sessions.
	for i := 0; i < 100; i++ {
		sid := fmt.Sprintf("session-%d", i)
		sa.RecordPageView(sid, "origin-1", "/", "")
		sa.RecordPageView(sid, "origin-1", "/products", "/")
		sa.RecordPageView(sid, "origin-1", "/cart", "/products")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sa.Stats("origin-1")
	}
}

func BenchmarkSessionAnalytics_Stats_AllOrigins(b *testing.B) {
	b.ReportAllocs()
	sa := NewSessionAnalytics(AnalyticsConfig{
		Enabled:        true,
		TrackPageFlow:  true,
		SessionTimeout: 30 * time.Minute,
	})
	origins := []string{"origin-1", "origin-2", "origin-3"}
	for i := 0; i < 100; i++ {
		sid := fmt.Sprintf("session-%d", i)
		origin := origins[i%len(origins)]
		sa.RecordPageView(sid, origin, "/", "")
		sa.RecordPageView(sid, origin, "/products", "/")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sa.Stats("")
	}
}
