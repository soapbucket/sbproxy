package fingerprint

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func BenchmarkBotDetector_Detect_BrowserLike(b *testing.B) {
	b.ReportAllocs()
	bd := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 70,
		TLSWeight:      0.3,
		BehaviorWeight: 0.4,
		HeaderWeight:   0.3,
	})
	fp := &Fingerprint{
		Hash:         "abc123",
		TLSHash:      "def456",
		ConnDuration: 50 * time.Millisecond,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bd.Detect(fp, req)
	}
}

func BenchmarkBotDetector_Detect_SuspiciousUA(b *testing.B) {
	b.ReportAllocs()
	bd := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 70,
		TLSWeight:      0.3,
		BehaviorWeight: 0.4,
		HeaderWeight:   0.3,
	})
	fp := &Fingerprint{
		Hash:    "abc123",
		TLSHash: "def456",
	}
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("User-Agent", "python-requests/2.28.0")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bd.Detect(fp, req)
	}
}

func BenchmarkBotDetector_Detect_NilFingerprint(b *testing.B) {
	b.ReportAllocs()
	bd := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 70,
		TLSWeight:      0.3,
		BehaviorWeight: 0.4,
		HeaderWeight:   0.3,
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bd.Detect(nil, req)
	}
}

func BenchmarkBotDetector_RecordRequest(b *testing.B) {
	b.ReportAllocs()
	bd := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 70,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bd.RecordRequest("client-1", req, 200)
	}
}
