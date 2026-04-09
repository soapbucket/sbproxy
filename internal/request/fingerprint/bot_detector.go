// Package fingerprint generates TLS and HTTP fingerprints (JA3, JA4) for client identification.
package fingerprint

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BotDetectorConfig configures bot detection.
type BotDetectorConfig struct {
	Enabled              bool          `json:"enabled,omitempty"`
	ScoreThreshold       float64       `json:"score_threshold,omitempty"`       // 0-100, above = bot (default: 70)
	TLSWeight            float64       `json:"tls_weight,omitempty"`            // Weight for TLS analysis (default: 0.3)
	BehaviorWeight       float64       `json:"behavior_weight,omitempty"`       // Weight for behavioral analysis (default: 0.4)
	HeaderWeight         float64       `json:"header_weight,omitempty"`         // Weight for header analysis (default: 0.3)
	TrackingWindow       time.Duration `json:"tracking_window,omitempty"`       // Behavior tracking window (default: 5m)
	KnownBotFingerprints []string      `json:"known_bot_fingerprints,omitempty"` // Known bot TLS fingerprints
}

// BotCategory classifies the type of bot detected.
type BotCategory string

const (
	BotCategoryHuman      BotCategory = "human"
	BotCategoryGoodBot    BotCategory = "good_bot"    // Search engines, monitoring
	BotCategoryBadBot     BotCategory = "bad_bot"     // Scrapers, credential stuffers
	BotCategoryUnknownBot BotCategory = "unknown_bot" // Automated but unclassified
)

// BotDetectionResult holds bot detection analysis.
type BotDetectionResult struct {
	IsBot         bool        `json:"is_bot"`
	Category      BotCategory `json:"category"`
	Score         float64     `json:"score"`           // 0-100, higher = more likely bot
	TLSScore      float64     `json:"tls_score"`       // TLS fingerprint score
	BehaviorScore float64     `json:"behavior_score"`  // Behavioral analysis score
	HeaderScore   float64     `json:"header_score"`    // Header analysis score
	Reasons       []string    `json:"reasons"`         // Why classified as bot
	Fingerprint   string      `json:"fingerprint"`     // JA3/JA4 hash
}

// BotDetectorStats holds bot detection metrics.
type BotDetectorStats struct {
	ChecksTotal    int64 `json:"checks_total"`
	BotsDetected   int64 `json:"bots_detected"`
	HumansDetected int64 `json:"humans_detected"`
}

// BotDetector combines TLS fingerprinting with behavioral analysis.
type BotDetector struct {
	config    BotDetectorConfig
	mu        sync.RWMutex
	behaviors map[string]*clientBehavior // keyed by IP or fingerprint hash
	knownBots map[string]bool            // known bot fingerprints

	// Good bot patterns (verified search engines, etc.)
	goodBotUA []string // User-Agent substrings for known good bots

	// Metrics
	checksTotal    atomic.Int64
	botsDetected   atomic.Int64
	humansDetected atomic.Int64
}

type clientBehavior struct {
	requestCount  int
	firstSeen     time.Time
	lastSeen      time.Time
	uniquePaths   map[string]bool
	avgInterval   time.Duration
	hasJavascript bool // Set JS challenge cookie
	hasCookies    bool
	userAgents    map[string]bool
	statusCodes   map[int]int
}

// NewBotDetector creates a new bot detector with the given config.
func NewBotDetector(config BotDetectorConfig) *BotDetector {
	if config.ScoreThreshold <= 0 {
		config.ScoreThreshold = 70
	}
	if config.TLSWeight <= 0 {
		config.TLSWeight = 0.3
	}
	if config.BehaviorWeight <= 0 {
		config.BehaviorWeight = 0.4
	}
	if config.HeaderWeight <= 0 {
		config.HeaderWeight = 0.3
	}
	if config.TrackingWindow <= 0 {
		config.TrackingWindow = 5 * time.Minute
	}

	knownBots := make(map[string]bool)
	for _, fp := range config.KnownBotFingerprints {
		knownBots[fp] = true
	}

	return &BotDetector{
		config:    config,
		behaviors: make(map[string]*clientBehavior),
		knownBots: knownBots,
		goodBotUA: []string{
			"Googlebot",
			"Bingbot",
			"bingbot",
			"Slurp",           // Yahoo
			"DuckDuckBot",
			"Baiduspider",
			"YandexBot",
			"facebot",         // Facebook
			"ia_archiver",     // Alexa
			"Uptimerobot",
			"Pingdom",
			"Site24x7",
			"StatusCake",
		},
	}
}

// Detect performs bot detection on a request using the provided fingerprint.
func (d *BotDetector) Detect(fp *Fingerprint, r *http.Request) *BotDetectionResult {
	d.checksTotal.Add(1)

	result := &BotDetectionResult{
		Category: BotCategoryHuman,
	}

	if fp != nil {
		result.Fingerprint = fp.TLSHash
	}

	// Determine the tracking key.
	key := ""
	if fp != nil && fp.Hash != "" {
		key = fp.Hash
	} else if r != nil {
		key = r.RemoteAddr
	}

	// Run analysis components.
	tlsScore, tlsReasons := d.analyzeTLS(fp)
	headerScore, headerReasons := d.analyzeHeaders(r)
	behaviorScore, behaviorReasons := d.analyzeBehavior(key)

	result.TLSScore = tlsScore
	result.HeaderScore = headerScore
	result.BehaviorScore = behaviorScore
	result.Reasons = append(result.Reasons, tlsReasons...)
	result.Reasons = append(result.Reasons, headerReasons...)
	result.Reasons = append(result.Reasons, behaviorReasons...)

	// Combine weighted scores.
	result.Score = tlsScore*d.config.TLSWeight +
		behaviorScore*d.config.BehaviorWeight +
		headerScore*d.config.HeaderWeight

	// A perfect TLS match against known bots is conclusive regardless of other signals.
	if tlsScore >= 100 {
		result.Score = 100
	}

	// Determine if this is a bot.
	result.IsBot = result.Score >= d.config.ScoreThreshold

	if result.IsBot {
		ua := ""
		if r != nil {
			ua = r.UserAgent()
		}
		result.Category = d.classifyBot(result.Score, ua)
		d.botsDetected.Add(1)
	} else {
		d.humansDetected.Add(1)
	}

	return result
}

// RecordRequest tracks a request for behavioral analysis.
func (d *BotDetector) RecordRequest(key string, r *http.Request, statusCode int) {
	if key == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	b, ok := d.behaviors[key]
	if !ok {
		b = &clientBehavior{
			firstSeen:   now,
			uniquePaths: make(map[string]bool),
			userAgents:  make(map[string]bool),
			statusCodes: make(map[int]int),
		}
		d.behaviors[key] = b
	}

	// Update behavior metrics.
	if b.requestCount > 0 {
		interval := now.Sub(b.lastSeen)
		// Running average of intervals.
		b.avgInterval = (b.avgInterval*time.Duration(b.requestCount-1) + interval) / time.Duration(b.requestCount)
	}

	b.requestCount++
	b.lastSeen = now

	if r != nil {
		b.uniquePaths[r.URL.Path] = true
		if ua := r.UserAgent(); ua != "" {
			b.userAgents[ua] = true
		}
		b.hasCookies = len(r.Cookies()) > 0
		if r.Header.Get("X-JS-Challenge") != "" {
			b.hasJavascript = true
		}
	}

	b.statusCodes[statusCode]++
}

// classifyBot determines the bot category based on score and user agent.
func (d *BotDetector) classifyBot(score float64, ua string) BotCategory {
	// Check for known good bots by user agent.
	if ua != "" {
		for _, goodUA := range d.goodBotUA {
			if strings.Contains(ua, goodUA) {
				return BotCategoryGoodBot
			}
		}
	}

	// High score with scraper-like patterns.
	if score >= 85 {
		return BotCategoryBadBot
	}

	return BotCategoryUnknownBot
}

// analyzeTLS scores the TLS fingerprint. Returns score (0-100) and reasons.
func (d *BotDetector) analyzeTLS(fp *Fingerprint) (float64, []string) {
	if fp == nil {
		return 50, []string{"no fingerprint available"}
	}

	var score float64
	var reasons []string

	// Check against known bot fingerprints.
	if fp.TLSHash != "" && d.knownBots[fp.TLSHash] {
		score = 100
		reasons = append(reasons, "known bot TLS fingerprint")
		return score, reasons
	}

	// No TLS hash at all is suspicious (plain HTTP or very old client).
	if fp.TLSHash == "" {
		score += 40
		reasons = append(reasons, "missing TLS fingerprint")
	}

	// Missing user agent hash is mildly suspicious.
	if fp.UserAgentHash == "" {
		score += 20
		reasons = append(reasons, "missing user agent hash")
	}

	// Very short connection duration can indicate automated tooling.
	if fp.ConnDuration > 0 && fp.ConnDuration < 10*time.Millisecond {
		score += 15
		reasons = append(reasons, "very fast connection setup")
	}

	if score > 100 {
		score = 100
	}
	return score, reasons
}

// analyzeHeaders scores request headers for bot indicators. Returns score (0-100) and reasons.
func (d *BotDetector) analyzeHeaders(r *http.Request) (float64, []string) {
	if r == nil {
		return 0, nil
	}

	var score float64
	var reasons []string

	ua := r.UserAgent()

	// Missing User-Agent is a strong bot signal.
	if ua == "" {
		score += 50
		reasons = append(reasons, "missing User-Agent header")
	}

	// Missing Accept header.
	if r.Header.Get("Accept") == "" {
		score += 20
		reasons = append(reasons, "missing Accept header")
	}

	// Missing Accept-Language for browser-like User-Agent.
	if r.Header.Get("Accept-Language") == "" && isBrowserUA(ua) {
		score += 25
		reasons = append(reasons, "browser UA but missing Accept-Language")
	}

	// Missing Accept-Encoding.
	if r.Header.Get("Accept-Encoding") == "" && isBrowserUA(ua) {
		score += 15
		reasons = append(reasons, "browser UA but missing Accept-Encoding")
	}

	// Connection header set to "close" for HTTP/1.1 is unusual for browsers.
	if r.ProtoMajor == 1 && r.ProtoMinor == 1 && r.Header.Get("Connection") == "close" {
		score += 10
		reasons = append(reasons, "Connection: close on HTTP/1.1")
	}

	// Suspicious User-Agent patterns.
	lowerUA := strings.ToLower(ua)
	botPatterns := []string{"python-requests", "python-urllib", "curl/", "wget/", "httpie/",
		"go-http-client", "java/", "libwww-perl", "mechanize", "scrapy", "headless"}
	for _, pattern := range botPatterns {
		if strings.Contains(lowerUA, pattern) {
			score += 30
			reasons = append(reasons, "suspicious User-Agent: "+pattern)
			break
		}
	}

	if score > 100 {
		score = 100
	}
	return score, reasons
}

// analyzeBehavior scores client behavior patterns. Returns score (0-100) and reasons.
func (d *BotDetector) analyzeBehavior(key string) (float64, []string) {
	if key == "" {
		return 0, nil
	}

	d.mu.RLock()
	b, ok := d.behaviors[key]
	if !ok {
		d.mu.RUnlock()
		return 0, nil
	}

	// Copy values under lock.
	requestCount := b.requestCount
	firstSeen := b.firstSeen
	lastSeen := b.lastSeen
	uniquePathCount := len(b.uniquePaths)
	avgInterval := b.avgInterval
	hasCookies := b.hasCookies
	hasJS := b.hasJavascript
	uaCount := len(b.userAgents)
	d.mu.RUnlock()

	// Only analyze if we have enough data.
	window := lastSeen.Sub(firstSeen)
	if window < 1*time.Second || requestCount < 3 {
		return 0, nil
	}

	var score float64
	var reasons []string

	// High request rate.
	rate := float64(requestCount) / window.Seconds()
	if rate > 10 {
		score += 40
		reasons = append(reasons, "high request rate")
	} else if rate > 5 {
		score += 20
		reasons = append(reasons, "elevated request rate")
	}

	// Very consistent timing (bots tend to be metronomic).
	if avgInterval > 0 && avgInterval < 500*time.Millisecond && requestCount > 10 {
		score += 25
		reasons = append(reasons, "metronomic request intervals")
	}

	// High path diversity in a short window (crawling behavior).
	if uniquePathCount > 20 && window < 2*time.Minute {
		score += 20
		reasons = append(reasons, "high path diversity")
	}

	// No cookies after many requests.
	if !hasCookies && requestCount > 5 {
		score += 15
		reasons = append(reasons, "no cookies after multiple requests")
	}

	// No JavaScript challenge response.
	if !hasJS && requestCount > 10 {
		score += 10
		reasons = append(reasons, "no JavaScript challenge response")
	}

	// Multiple User-Agents from the same fingerprint/IP.
	if uaCount > 1 {
		score += 20
		reasons = append(reasons, "multiple User-Agents from same client")
	}

	if score > 100 {
		score = 100
	}
	return score, reasons
}

// Cleanup removes expired behavior entries outside the tracking window.
func (d *BotDetector) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-d.config.TrackingWindow)
	for key, b := range d.behaviors {
		if b.lastSeen.Before(cutoff) {
			delete(d.behaviors, key)
		}
	}
}

// Stats returns bot detection metrics.
func (d *BotDetector) Stats() BotDetectorStats {
	return BotDetectorStats{
		ChecksTotal:    d.checksTotal.Load(),
		BotsDetected:   d.botsDetected.Load(),
		HumansDetected: d.humansDetected.Load(),
	}
}

// isBrowserUA returns true if the User-Agent looks like a standard web browser.
func isBrowserUA(ua string) bool {
	if ua == "" {
		return false
	}
	lower := strings.ToLower(ua)
	return strings.Contains(lower, "mozilla/") ||
		strings.Contains(lower, "chrome/") ||
		strings.Contains(lower, "safari/") ||
		strings.Contains(lower, "firefox/") ||
		strings.Contains(lower, "edge/")
}
