package ai

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func BenchmarkComputeSessionKey(b *testing.B) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-1234567890abcdef")
	req.Header.Set("X-API-Key", "key-abc123")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		m.ComputeSessionKey(req)
	}
}

func BenchmarkComputeSessionKeyWithCookies(b *testing.B) {
	cfg := &StickySessionConfig{
		Enabled:     true,
		TTL:         time.Minute,
		HashCookies: []string{"session_id", "tracking"},
	}
	m := NewStickySessionManager(cfg)
	defer m.Stop()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-1234567890abcdef")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "sess-abc123"})
	req.AddCookie(&http.Cookie{Name: "tracking", Value: "track-xyz789"})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		m.ComputeSessionKey(req)
	}
}

func BenchmarkGetStickyProvider(b *testing.B) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	// Pre-populate
	m.SetStickyProvider("bench-key", "openai")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		m.GetStickyProvider("bench-key")
	}
}

func BenchmarkGetStickyProviderMiss(b *testing.B) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		m.GetStickyProvider("nonexistent-key")
	}
}

func BenchmarkSetStickyProvider(b *testing.B) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		m.SetStickyProvider(fmt.Sprintf("key-%d", i), "openai")
	}
}

func BenchmarkSetStickyProviderOverwrite(b *testing.B) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	// Pre-populate with a single key
	m.SetStickyProvider("overwrite-key", "openai")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		m.SetStickyProvider("overwrite-key", "anthropic")
	}
}

func BenchmarkStickyProviderConcurrent(b *testing.B) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	// Pre-populate
	for i := 0; i < 1000; i++ {
		m.SetStickyProvider(fmt.Sprintf("key-%d", i), "openai")
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key-%d", i%1000)
			if i%3 == 0 {
				m.SetStickyProvider(key, "anthropic")
			} else {
				m.GetStickyProvider(key)
			}
			i++
		}
	})
}
