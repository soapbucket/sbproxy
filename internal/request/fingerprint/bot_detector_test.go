package fingerprint

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBotDetector_Human(t *testing.T) {
	t.Parallel()

	detector := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 70,
	})

	fp := &Fingerprint{
		Hash:          "abc123",
		TLSHash:       "ja3-normal-browser",
		UserAgentHash: "ua-hash-chrome",
		ConnDuration:  150 * time.Millisecond,
	}

	r := httptest.NewRequest(http.MethodGet, "/page", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")

	result := detector.Detect(fp, r)

	if result.IsBot {
		t.Errorf("expected human, got bot (score: %.1f, reasons: %v)", result.Score, result.Reasons)
	}
	if result.Category != BotCategoryHuman {
		t.Errorf("expected category human, got %s", result.Category)
	}
}

func TestBotDetector_KnownBotFingerprint(t *testing.T) {
	t.Parallel()

	knownBotTLS := "ja3-known-scraper"

	detector := NewBotDetector(BotDetectorConfig{
		Enabled:              true,
		ScoreThreshold:       70,
		KnownBotFingerprints: []string{knownBotTLS},
	})

	fp := &Fingerprint{
		Hash:          "bot-hash",
		TLSHash:       knownBotTLS,
		UserAgentHash: "ua-bot",
		ConnDuration:  5 * time.Millisecond,
	}

	r := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")

	result := detector.Detect(fp, r)

	if !result.IsBot {
		t.Errorf("expected bot detection for known fingerprint, score: %.1f", result.Score)
	}
	if result.TLSScore != 100 {
		t.Errorf("expected TLS score 100, got %.1f", result.TLSScore)
	}

	foundReason := false
	for _, reason := range result.Reasons {
		if reason == "known bot TLS fingerprint" {
			foundReason = true
			break
		}
	}
	if !foundReason {
		t.Errorf("expected 'known bot TLS fingerprint' reason, got: %v", result.Reasons)
	}
}

func TestBotDetector_HeaderAnomalies(t *testing.T) {
	t.Parallel()

	detector := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 70,
	})

	fp := &Fingerprint{
		Hash:          "client-hash",
		TLSHash:       "some-tls-hash",
		UserAgentHash: "ua-hash",
	}

	// Request with no standard headers (bot-like).
	r := httptest.NewRequest(http.MethodGet, "/data", nil)
	// Clear all headers.
	r.Header = http.Header{}

	result := detector.Detect(fp, r)

	if result.HeaderScore < 50 {
		t.Errorf("expected high header score for missing headers, got %.1f", result.HeaderScore)
	}

	hasUAMissing := false
	for _, reason := range result.Reasons {
		if reason == "missing User-Agent header" {
			hasUAMissing = true
			break
		}
	}
	if !hasUAMissing {
		t.Errorf("expected 'missing User-Agent header' reason, got: %v", result.Reasons)
	}
}

func TestBotDetector_BehavioralAnalysis(t *testing.T) {
	t.Parallel()

	detector := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 70,
		TrackingWindow: 5 * time.Minute,
	})

	key := "rapid-client"

	// Manually build up behavior data with synthetic timing to simulate rapid requests.
	detector.mu.Lock()
	detector.behaviors[key] = &clientBehavior{
		requestCount:  50,
		firstSeen:     time.Now().Add(-2 * time.Second),
		lastSeen:      time.Now(),
		uniquePaths:   map[string]bool{"/": true, "/a": true, "/b": true},
		avgInterval:   40 * time.Millisecond,
		hasCookies:    false,
		hasJavascript: false,
		userAgents:    map[string]bool{"bot-agent": true},
		statusCodes:   map[int]int{200: 50},
	}
	detector.mu.Unlock()

	// Now run detection with behavior data.
	fp := &Fingerprint{
		Hash:    key,
		TLSHash: "some-tls",
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", "bot-agent")
	r.Header.Set("Accept", "text/html")

	result := detector.Detect(fp, r)

	if result.BehaviorScore == 0 {
		t.Error("expected non-zero behavior score for rapid requests")
	}

	// The combined score should be elevated due to high request rate and no cookies.
	if result.Score < 20 {
		t.Errorf("expected elevated score for rapid requests, got %.1f", result.Score)
	}
}

func TestBotDetector_GoodBot(t *testing.T) {
	t.Parallel()

	detector := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 30, // Low threshold so the Googlebot UA triggers detection.
	})

	fp := &Fingerprint{
		Hash:    "google-bot-hash",
		TLSHash: "", // Googlebot may not have a TLS hash in some scenarios.
	}

	r := httptest.NewRequest(http.MethodGet, "/page", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	r.Header.Set("Accept", "*/*")
	// Note: Googlebot has a browser-like UA but missing Accept-Language triggers header score.

	result := detector.Detect(fp, r)

	// With low threshold the missing TLS + Accept-Language should push it over.
	if result.IsBot && result.Category != BotCategoryGoodBot {
		t.Errorf("expected good_bot category for Googlebot, got %s", result.Category)
	}
}

func TestBotDetector_Cleanup(t *testing.T) {
	t.Parallel()

	detector := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		TrackingWindow: 100 * time.Millisecond,
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	detector.RecordRequest("old-client", r, 200)

	// Wait for the tracking window to expire.
	time.Sleep(200 * time.Millisecond)

	detector.RecordRequest("new-client", r, 200)

	detector.Cleanup()

	detector.mu.RLock()
	_, hasOld := detector.behaviors["old-client"]
	_, hasNew := detector.behaviors["new-client"]
	detector.mu.RUnlock()

	if hasOld {
		t.Error("expected old-client to be cleaned up")
	}
	if !hasNew {
		t.Error("expected new-client to remain")
	}
}

func TestBotDetector_SuspiciousUA(t *testing.T) {
	t.Parallel()

	detector := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 70,
	})

	fp := &Fingerprint{
		Hash:    "curl-client",
		TLSHash: "some-tls",
	}

	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	r.Header.Set("User-Agent", "curl/7.88.0")
	r.Header.Set("Accept", "*/*")

	result := detector.Detect(fp, r)

	hasSuspiciousUA := false
	for _, reason := range result.Reasons {
		if reason == "suspicious User-Agent: curl/" {
			hasSuspiciousUA = true
			break
		}
	}
	if !hasSuspiciousUA {
		t.Errorf("expected 'suspicious User-Agent: curl/' reason, got: %v", result.Reasons)
	}

	if result.HeaderScore < 30 {
		t.Errorf("expected header score >= 30 for curl UA, got %.1f", result.HeaderScore)
	}
}

func TestBotDetector_Stats(t *testing.T) {
	t.Parallel()

	detector := NewBotDetector(BotDetectorConfig{
		Enabled:        true,
		ScoreThreshold: 70,
	})

	fp := &Fingerprint{
		Hash:          "normal",
		TLSHash:       "tls-hash",
		UserAgentHash: "ua-hash",
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en-US")
	r.Header.Set("Accept-Encoding", "gzip")

	detector.Detect(fp, r)
	detector.Detect(fp, r)

	stats := detector.Stats()
	if stats.ChecksTotal != 2 {
		t.Errorf("expected 2 checks, got %d", stats.ChecksTotal)
	}
}
