// Package ddos registers the ddos_protection policy.
package ddos

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/soapbucket/sbproxy/internal/middleware/callback"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("ddos_protection", New)
}

// ---- Config types ----

// DetectionConfig holds detection configuration.
type DetectionConfig struct {
	RequestRateThreshold    int     `json:"request_rate_threshold,omitempty"`
	ConnectionRateThreshold int     `json:"connection_rate_threshold,omitempty"`
	BandwidthThreshold      string  `json:"bandwidth_threshold,omitempty"`
	DetectionWindow         string  `json:"detection_window,omitempty"`
	AdaptiveThresholds      bool    `json:"adaptive_thresholds,omitempty"`
	BaselineWindow          string  `json:"baseline_window,omitempty"`
	ThresholdMultiplier     float64 `json:"threshold_multiplier,omitempty"`
}

// ProofOfWorkConfig holds proof-of-work configuration.
type ProofOfWorkConfig struct {
	Enabled    bool   `json:"enabled,omitempty"`
	Difficulty int    `json:"difficulty,omitempty"`
	Timeout    string `json:"timeout,omitempty"`
	HeaderName string `json:"header_name,omitempty"`
}

// JavaScriptChallengeConfig holds JavaScript challenge configuration.
type JavaScriptChallengeConfig struct {
	Enabled    bool   `json:"enabled,omitempty"`
	ScriptPath string `json:"script_path,omitempty"`
	Timeout    string `json:"timeout,omitempty"`
	HeaderName string `json:"header_name,omitempty"`
}

// CAPTCHAConfig holds CAPTCHA configuration.
type CAPTCHAConfig struct {
	Enabled   bool   `json:"enabled,omitempty"`
	Provider  string `json:"provider,omitempty"`
	SiteKey   string `json:"site_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	VerifyURL string `json:"verify_url,omitempty"`
}

// MitigationConfig holds mitigation configuration.
type MitigationConfig struct {
	BlockDuration       string                     `json:"block_duration,omitempty"`
	ChallengeResponse   bool                       `json:"challenge_response,omitempty"`
	ChallengeType       string                     `json:"challenge_type,omitempty"`
	ProofOfWork         *ProofOfWorkConfig         `json:"proof_of_work,omitempty"`
	JavaScriptChallenge *JavaScriptChallengeConfig `json:"javascript_challenge,omitempty"`
	CAPTCHA             *CAPTCHAConfig             `json:"captcha,omitempty"`
	AutoBlock           bool                       `json:"auto_block,omitempty"`
	BlockAfterAttacks   int                        `json:"block_after_attacks,omitempty"`
	CustomHTMLCallback  json.RawMessage            `json:"custom_html_callback,omitempty"`
}

// Config holds configuration for the ddos_protection policy.
type Config struct {
	Type       string            `json:"type"`
	Disabled   bool              `json:"disabled,omitempty"`
	Detection  *DetectionConfig  `json:"detection,omitempty"`
	Mitigation *MitigationConfig `json:"mitigation,omitempty"`
}

// New creates a new ddos_protection policy enforcer.
func New(data json.RawMessage) (plugin.PolicyEnforcer, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Memory budget per origin:
	// Each LRU map entry is ~120 bytes (key string + value + linked list pointers).
	// requestCounts (50k) + connectionCounts (50k) + bandwidthCounts (50k) = ~18MB
	// blockedIPs (100k) = ~12MB
	// Total per origin: ~30MB (actual may vary with key lengths).
	// For multi-tenant deployments with many origins, consider reducing these sizes
	// or making them configurable via the DDoS policy config.
	p := &ddosPolicy{
		cfg:              cfg,
		requestCounts:    newLRUMap(50000),
		connectionCounts: newLRUMap(50000),
		bandwidthCounts:  newLRUMap(50000),
		blockedIPs:       newLRUMap(100000),
		challengeIPs:     newLRUMap(100000),
		attackHistory:    newLRUMap(10000),
		baseline:         &trafficBaseline{},
		lastCleanupNano:  time.Now().UnixNano(),
	}

	// Set defaults.
	if cfg.Mitigation != nil {
		if cfg.Mitigation.ChallengeType == "" {
			cfg.Mitigation.ChallengeType = "header"
		}
		if cfg.Mitigation.BlockAfterAttacks == 0 {
			cfg.Mitigation.BlockAfterAttacks = 3
		}
		if cfg.Mitigation.ProofOfWork != nil && cfg.Mitigation.ProofOfWork.Difficulty == 0 {
			cfg.Mitigation.ProofOfWork.Difficulty = 4
		}
		if cfg.Mitigation.ProofOfWork != nil && cfg.Mitigation.ProofOfWork.HeaderName == "" {
			cfg.Mitigation.ProofOfWork.HeaderName = "X-Proof-Of-Work"
		}
		if cfg.Mitigation.JavaScriptChallenge != nil && cfg.Mitigation.JavaScriptChallenge.HeaderName == "" {
			cfg.Mitigation.JavaScriptChallenge.HeaderName = "X-JS-Challenge"
		}
		// Unmarshal custom HTML callback.
		if len(cfg.Mitigation.CustomHTMLCallback) > 0 {
			var cb callback.Callback
			if err := json.Unmarshal(cfg.Mitigation.CustomHTMLCallback, &cb); err == nil {
				p.customHTMLCallback = &cb
			}
		}
	}

	if cfg.Detection != nil {
		if cfg.Detection.ThresholdMultiplier == 0 {
			cfg.Detection.ThresholdMultiplier = 2.0
		}
		if cfg.Detection.BaselineWindow == "" {
			cfg.Detection.BaselineWindow = "1h"
		}
	}

	return p, nil
}

type ddosPolicy struct {
	cfg              *Config
	requestCounts    *lruMap
	connectionCounts *lruMap
	bandwidthCounts  *lruMap
	blockedIPs       *lruMap
	challengeIPs     *lruMap
	attackHistory    *lruMap
	baseline         *trafficBaseline
	lastCleanupNano  int64 // atomic, unix nanos
	customHTMLCallback *callback.Callback
	cleanupMu        sync.Mutex   // protects cleanup only, not per-IP detection
	mu               sync.RWMutex // protects baseline and handleAttack
	ctx              context.Context
	cancel           context.CancelFunc
	// Fields from PluginContext.
	originID string
}

func (p *ddosPolicy) Type() string { return "ddos_protection" }

// InitPlugin implements plugin.Initable.
func (p *ddosPolicy) InitPlugin(ctx plugin.PluginContext) error {
	p.originID = ctx.OriginID
	p.ctx, p.cancel = context.WithCancel(context.Background())
	go p.cleanup()
	if p.cfg.Detection != nil && p.cfg.Detection.AdaptiveThresholds {
		go p.updateBaseline()
	}
	return nil
}

func (p *ddosPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := getClientIPFromRequest(r)
		if clientIP == "" {
			next.ServeHTTP(w, r)
			return
		}

		if p.isBlocked(clientIP) {
			logging.LogSecurityEvent(r.Context(), logging.SecurityEventDDoSAttack, logging.SeverityHigh, "ddos_check", "blocked",
				zap.String("ip", clientIP),
				zap.String("reason", "ip_blocked"),
			)
			reqctx.RecordPolicyViolation(r.Context(), "ddos", "IP temporarily blocked due to suspicious activity")
			http.Error(w, "IP temporarily blocked due to suspicious activity", http.StatusTooManyRequests)
			return
		}

		if p.needsChallenge(clientIP) {
			resp := p.handleChallenge(r, clientIP)
			if resp != nil {
				w.WriteHeader(resp.StatusCode)
				if resp.Body != nil {
					defer resp.Body.Close()
					var buf []byte
					buf, _ = io.ReadAll(resp.Body)
					_, _ = w.Write(buf)
				}
			} else {
				next.ServeHTTP(w, r)
			}
			return
		}

		if p.cfg.Detection != nil {
			attack := p.detectAttack(clientIP, r)
			if attack != nil {
				origin := p.originID
				if origin == "" {
					origin = "unknown"
				}
				metric.DDoSAttackDetected(origin, attack.Type, attack.IP)
				p.handleAttack(attack)
				logging.LogSecurityEvent(r.Context(), logging.SecurityEventDDoSAttack, logging.SeverityHigh, "ddos_check", "detected",
					zap.String("ip", attack.IP),
					zap.String("threat_type", attack.Type),
				)
				reqctx.RecordPolicyViolation(r.Context(), "ddos", "Suspicious activity detected")
				http.Error(w, "Suspicious activity detected", http.StatusTooManyRequests)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// ---- Internal types ----

type requestWindow struct {
	count     int
	windowEnd time.Time
}

type bandwidthWindow struct {
	bytes     int64
	windowEnd time.Time
}

type blockInfo struct {
	blockedUntil time.Time
	attackCount  int
}

type challengeInfo struct {
	challengeType string
	challengeData string
	expiresAt     time.Time
}

type trafficBaseline struct {
	avgRequestRate    float64
	avgConnectionRate float64
	avgBandwidth      float64
	lastUpdated       time.Time
}

type attackInfo struct {
	Type       string
	IP         string
	Count      int
	Threshold  int
	DetectedAt time.Time
}

// ---- Detection ----

// detectAttack checks whether clientIP exceeds configured rate thresholds.
//
// Concurrency note: this method does NOT hold the outer p.mu lock. Each lruMap
// has its own internal mutex, so per-IP reads and writes are safe. The trade-off
// is that threshold reads from p.baseline (used by adaptive thresholds) may see
// a slightly stale snapshot, but this is acceptable for DDoS heuristics. Holding
// p.mu for the entire detection flow would serialize all incoming requests and
// become a bottleneck under high load. Per-IP sharding of the lruMaps could
// further reduce contention but adds complexity with limited benefit since the
// internal map locks are already per-map, not global.
func (p *ddosPolicy) detectAttack(clientIP string, req *http.Request) *attackInfo {
	now := time.Now()
	window := p.getDetectionWindow()

	// Periodic cleanup uses a separate mutex so it does not block per-IP detection.
	// The lruMaps have their own internal locks, so per-IP reads/writes are safe
	// without holding the outer lock.
	lastClean := time.Unix(0, atomic.LoadInt64(&p.lastCleanupNano))
	if now.Sub(lastClean) > window {
		p.cleanupMu.Lock()
		// Double-check after acquiring lock
		lastClean = time.Unix(0, atomic.LoadInt64(&p.lastCleanupNano))
		if now.Sub(lastClean) > window {
			p.cleanupLocked()
			atomic.StoreInt64(&p.lastCleanupNano, now.UnixNano())
		}
		p.cleanupMu.Unlock()
	}

	requestThreshold := p.getRequestThreshold()
	connectionThreshold := p.getConnectionThreshold()
	bandwidthThreshold := p.getBandwidthThreshold()

	if requestThreshold > 0 {
		var rw *requestWindow
		if val, exists := p.requestCounts.getAndUpdate(clientIP); exists {
			rw = val.(*requestWindow)
		}
		if rw == nil || now.After(rw.windowEnd) {
			rw = &requestWindow{count: 0, windowEnd: now.Add(window)}
		}
		rw.count++
		p.requestCounts.set(clientIP, rw)
		if rw.count > requestThreshold {
			return &attackInfo{
				Type:       "request_rate",
				IP:         clientIP,
				Count:      rw.count,
				Threshold:  requestThreshold,
				DetectedAt: now,
			}
		}
	}

	if connectionThreshold > 0 {
		var cw *requestWindow
		if val, exists := p.connectionCounts.getAndUpdate(clientIP); exists {
			cw = val.(*requestWindow)
		}
		if cw == nil || now.After(cw.windowEnd) {
			cw = &requestWindow{count: 0, windowEnd: now.Add(window)}
		}
		cw.count++
		p.connectionCounts.set(clientIP, cw)
		if cw.count > connectionThreshold {
			return &attackInfo{
				Type:       "connection_rate",
				IP:         clientIP,
				Count:      cw.count,
				Threshold:  connectionThreshold,
				DetectedAt: now,
			}
		}
	}

	if bandwidthThreshold > 0 {
		contentLength := req.ContentLength
		if contentLength < 0 {
			contentLength = 0
		}
		var bw *bandwidthWindow
		if val, exists := p.bandwidthCounts.getAndUpdate(clientIP); exists {
			bw = val.(*bandwidthWindow)
		}
		if bw == nil || now.After(bw.windowEnd) {
			bw = &bandwidthWindow{bytes: 0, windowEnd: now.Add(window)}
		}
		bw.bytes += contentLength
		p.bandwidthCounts.set(clientIP, bw)
		if bw.bytes > bandwidthThreshold {
			return &attackInfo{
				Type:       "bandwidth",
				IP:         clientIP,
				Count:      int(bw.bytes),
				Threshold:  int(bandwidthThreshold),
				DetectedAt: now,
			}
		}
	}

	return nil
}

func (p *ddosPolicy) getRequestThreshold() int {
	if p.cfg.Detection == nil {
		return 0
	}
	if p.cfg.Detection.AdaptiveThresholds && p.baseline.avgRequestRate > 0 {
		return int(p.baseline.avgRequestRate * p.cfg.Detection.ThresholdMultiplier)
	}
	return p.cfg.Detection.RequestRateThreshold
}

func (p *ddosPolicy) getConnectionThreshold() int {
	if p.cfg.Detection == nil {
		return 0
	}
	if p.cfg.Detection.AdaptiveThresholds && p.baseline.avgConnectionRate > 0 {
		return int(p.baseline.avgConnectionRate * p.cfg.Detection.ThresholdMultiplier)
	}
	return p.cfg.Detection.ConnectionRateThreshold
}

func (p *ddosPolicy) getBandwidthThreshold() int64 {
	if p.cfg.Detection == nil {
		return 0
	}
	if p.cfg.Detection.BandwidthThreshold == "" {
		return 0
	}
	threshold := parseBandwidthThreshold(p.cfg.Detection.BandwidthThreshold)
	if p.cfg.Detection.AdaptiveThresholds && p.baseline.avgBandwidth > 0 {
		return int64(p.baseline.avgBandwidth * p.cfg.Detection.ThresholdMultiplier)
	}
	return threshold
}

func (p *ddosPolicy) getDetectionWindow() time.Duration {
	if p.cfg.Detection == nil || p.cfg.Detection.DetectionWindow == "" {
		return 10 * time.Second
	}
	window, err := time.ParseDuration(p.cfg.Detection.DetectionWindow)
	if err != nil {
		return 10 * time.Second
	}
	return window
}

// ---- Mitigation ----

func (p *ddosPolicy) handleAttack(attack *attackInfo) {
	if p.cfg.Mitigation == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	var attacks []time.Time
	if val, exists := p.attackHistory.get(attack.IP); exists {
		attacks = val.([]time.Time)
	}
	attacks = append(attacks, attack.DetectedAt)

	cutoff := time.Now().Add(-time.Hour)
	filtered := make([]time.Time, 0, len(attacks))
	for _, t := range attacks {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	p.attackHistory.set(attack.IP, filtered)
	attackCount := len(filtered)

	if p.cfg.Mitigation.AutoBlock && attackCount >= p.cfg.Mitigation.BlockAfterAttacks {
		blockDuration, err := time.ParseDuration(p.cfg.Mitigation.BlockDuration)
		if err != nil {
			blockDuration = time.Hour
		}
		bi := &blockInfo{
			blockedUntil: time.Now().Add(blockDuration),
			attackCount:  attackCount,
		}
		p.blockedIPs.set(attack.IP, bi)
		return
	}

	if p.cfg.Mitigation.ChallengeResponse {
		challengeDuration := 5 * time.Minute
		if p.cfg.Mitigation.ProofOfWork != nil && p.cfg.Mitigation.ProofOfWork.Timeout != "" {
			if d, err := time.ParseDuration(p.cfg.Mitigation.ProofOfWork.Timeout); err == nil {
				challengeDuration = d
			}
		}

		ci := &challengeInfo{
			challengeType: p.cfg.Mitigation.ChallengeType,
			expiresAt:     time.Now().Add(challengeDuration),
		}

		switch p.cfg.Mitigation.ChallengeType {
		case "proof_of_work":
			ci.challengeData = fmt.Sprintf("pow_%s_%d", attack.IP, time.Now().Unix())
		case "javascript":
			ci.challengeData = fmt.Sprintf("js_%s_%d", attack.IP, time.Now().Unix())
		case "captcha":
			ci.challengeData = fmt.Sprintf("captcha_%s_%d", attack.IP, time.Now().Unix())
		default:
			ci.challengeData = fmt.Sprintf("challenge_%s", attack.IP)
		}

		p.challengeIPs.set(attack.IP, ci)
	}
}

func (p *ddosPolicy) isBlocked(ip string) bool {
	val, exists := p.blockedIPs.get(ip)
	if !exists {
		return false
	}

	bi := val.(*blockInfo)
	if time.Now().After(bi.blockedUntil) {
		p.blockedIPs.delete(ip)
		p.attackHistory.delete(ip)
		return false
	}
	return true
}

func (p *ddosPolicy) needsChallenge(ip string) bool {
	val, exists := p.challengeIPs.get(ip)
	if !exists {
		return false
	}

	ci := val.(*challengeInfo)
	if time.Now().After(ci.expiresAt) {
		p.challengeIPs.delete(ip)
		return false
	}
	return true
}

func (p *ddosPolicy) handleChallenge(req *http.Request, clientIP string) *http.Response {
	if p.cfg.Mitigation == nil || !p.cfg.Mitigation.ChallengeResponse {
		return createErrorResponse(http.StatusTooManyRequests, "Challenge verification failed")
	}

	val, exists := p.challengeIPs.get(clientIP)
	if !exists {
		return createErrorResponse(http.StatusTooManyRequests, "Challenge not found")
	}

	ci := val.(*challengeInfo)

	switch ci.challengeType {
	case "proof_of_work":
		return p.handleProofOfWorkChallenge(req, clientIP, ci)
	case "javascript":
		return p.handleJavaScriptChallenge(req, clientIP, ci)
	case "captcha":
		return p.handleCAPTCHAChallenge(req, clientIP, ci)
	default:
		return p.handleHeaderChallenge(req, clientIP, ci)
	}
}

func (p *ddosPolicy) handleHeaderChallenge(req *http.Request, clientIP string, ci *challengeInfo) *http.Response {
	challengeHeader := req.Header.Get("X-Challenge-Response")
	if challengeHeader == "" {
		htmlContent := p.getCustomChallengeHTML(req, ci, "header")
		if htmlContent != "" {
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(htmlContent)),
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html")
			return resp
		}
		response := fmt.Sprintf(`{"error":"challenge_required","message":"Please complete the challenge to continue","challenge":"%s","instructions":"Add X-Challenge-Response header with the challenge value"}`, ci.challengeData)
		return createJSONErrorResponse(http.StatusTooManyRequests, response)
	}
	if req.Header.Get("X-Challenge-Response") == fmt.Sprintf("challenge_%s", clientIP) {
		p.challengeIPs.delete(clientIP)
		return nil
	}
	return createErrorResponse(http.StatusTooManyRequests, "Challenge verification failed")
}

func (p *ddosPolicy) handleProofOfWorkChallenge(req *http.Request, clientIP string, ci *challengeInfo) *http.Response {
	if p.cfg.Mitigation.ProofOfWork == nil || !p.cfg.Mitigation.ProofOfWork.Enabled {
		return createErrorResponse(http.StatusTooManyRequests, "Proof-of-work challenge not configured")
	}

	powHeader := req.Header.Get(p.cfg.Mitigation.ProofOfWork.HeaderName)
	if powHeader == "" {
		htmlContent := p.getCustomChallengeHTML(req, ci, "proof_of_work")
		if htmlContent != "" {
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(htmlContent)),
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html")
			return resp
		}
		difficulty := p.cfg.Mitigation.ProofOfWork.Difficulty
		response := fmt.Sprintf(`{"error":"proof_of_work_required","message":"Please complete the proof-of-work challenge","challenge":"%s","difficulty":%d,"instructions":"Find a nonce such that SHA256(challenge + nonce) has %d leading zeros. Submit the nonce in the %s header."}`,
			ci.challengeData, difficulty, difficulty, p.cfg.Mitigation.ProofOfWork.HeaderName)
		return createJSONErrorResponse(http.StatusTooManyRequests, response)
	}

	if verifyProofOfWork(ci.challengeData, powHeader, p.cfg.Mitigation.ProofOfWork.Difficulty) {
		p.challengeIPs.delete(clientIP)
		return nil
	}
	return createErrorResponse(http.StatusTooManyRequests, "Proof-of-work verification failed")
}

func (p *ddosPolicy) handleJavaScriptChallenge(req *http.Request, clientIP string, ci *challengeInfo) *http.Response {
	if p.cfg.Mitigation.JavaScriptChallenge == nil || !p.cfg.Mitigation.JavaScriptChallenge.Enabled {
		return createErrorResponse(http.StatusTooManyRequests, "JavaScript challenge not configured")
	}

	jsHeader := req.Header.Get(p.cfg.Mitigation.JavaScriptChallenge.HeaderName)
	if jsHeader == "" {
		htmlContent := p.getCustomChallengeHTML(req, ci, "javascript")
		if htmlContent == "" {
			jsScript := fmt.Sprintf(`(function(){var challenge='%s';var result=btoa(challenge+'_'+navigator.userAgent+'_'+Date.now());var xhr=new XMLHttpRequest();xhr.open('POST',window.location.href,true);xhr.setRequestHeader('%s',result);xhr.onload=function(){if(xhr.status===200){window.location.reload();}};xhr.send();})();`,
				ci.challengeData, p.cfg.Mitigation.JavaScriptChallenge.HeaderName)
			htmlContent = fmt.Sprintf(`<!DOCTYPE html><html><head><title>Security Challenge</title></head><body><h1>Security Challenge</h1><p>Please wait while we verify your browser...</p><script>%s</script></body></html>`, html.EscapeString(jsScript))
		}
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(htmlContent)),
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")
		return resp
	}

	if strings.Contains(jsHeader, ci.challengeData) {
		p.challengeIPs.delete(clientIP)
		return nil
	}
	return createErrorResponse(http.StatusTooManyRequests, "JavaScript challenge verification failed")
}

func (p *ddosPolicy) handleCAPTCHAChallenge(req *http.Request, clientIP string, ci *challengeInfo) *http.Response {
	if p.cfg.Mitigation.CAPTCHA == nil || !p.cfg.Mitigation.CAPTCHA.Enabled {
		return createErrorResponse(http.StatusTooManyRequests, "CAPTCHA challenge not configured")
	}

	captchaToken := req.Header.Get("X-CAPTCHA-Token")
	if captchaToken == "" {
		htmlContent := p.getCustomChallengeHTML(req, ci, "captcha")
		if htmlContent == "" {
			htmlContent = getCAPTCHAChallengeHTML(p.cfg.Mitigation.CAPTCHA)
		}
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(htmlContent)),
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")
		return resp
	}

	if verifyCAPTCHA(captchaToken, clientIP, p.cfg.Mitigation.CAPTCHA) {
		p.challengeIPs.delete(clientIP)
		return nil
	}
	return createErrorResponse(http.StatusTooManyRequests, "CAPTCHA verification failed")
}

func (p *ddosPolicy) getCustomChallengeHTML(req *http.Request, ci *challengeInfo, challengeType string) string {
	if p.customHTMLCallback == nil {
		return ""
	}

	callbackData := map[string]any{
		"challenge_type": challengeType,
		"challenge_data": ci.challengeData,
		"client_ip":      getClientIPFromRequest(req),
		"user_agent":     req.UserAgent(),
		"request_path":   req.URL.Path,
		"request_method": req.Method,
	}

	switch challengeType {
	case "proof_of_work":
		if p.cfg.Mitigation.ProofOfWork != nil {
			callbackData["difficulty"] = p.cfg.Mitigation.ProofOfWork.Difficulty
			callbackData["header_name"] = p.cfg.Mitigation.ProofOfWork.HeaderName
			callbackData["timeout"] = p.cfg.Mitigation.ProofOfWork.Timeout
		}
	case "javascript":
		if p.cfg.Mitigation.JavaScriptChallenge != nil {
			callbackData["header_name"] = p.cfg.Mitigation.JavaScriptChallenge.HeaderName
			callbackData["timeout"] = p.cfg.Mitigation.JavaScriptChallenge.Timeout
		}
	case "captcha":
		if p.cfg.Mitigation.CAPTCHA != nil {
			callbackData["provider"] = p.cfg.Mitigation.CAPTCHA.Provider
			callbackData["site_key"] = p.cfg.Mitigation.CAPTCHA.SiteKey
		}
	}

	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()

	fetchResp, err := p.customHTMLCallback.Fetch(ctx, callbackData)
	if err != nil {
		return ""
	}

	if fetchResp != nil && len(fetchResp.Body) > 0 {
		return string(fetchResp.Body)
	}
	return ""
}

// ---- Baseline ----

func (p *ddosPolicy) updateBaseline() {
	if p.cfg.Detection == nil || !p.cfg.Detection.AdaptiveThresholds {
		return
	}
	baselineWindow, err := time.ParseDuration(p.cfg.Detection.BaselineWindow)
	if err != nil {
		baselineWindow = time.Hour
	}
	ticker := time.NewTicker(baselineWindow / 4)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.calculateBaseline()
		}
	}
}

func (p *ddosPolicy) calculateBaseline() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	totalRequests := 0
	totalConnections := 0
	var totalBandwidth int64
	count := 0

	for _, key := range p.requestCounts.snapshot() {
		if val, exists := p.requestCounts.get(key); exists {
			rw := val.(*requestWindow)
			if now.Before(rw.windowEnd) {
				totalRequests += rw.count
				count++
			}
		}
	}
	for _, key := range p.connectionCounts.snapshot() {
		if val, exists := p.connectionCounts.get(key); exists {
			cw := val.(*requestWindow)
			if now.Before(cw.windowEnd) {
				totalConnections += cw.count
			}
		}
	}
	for _, key := range p.bandwidthCounts.snapshot() {
		if val, exists := p.bandwidthCounts.get(key); exists {
			bw := val.(*bandwidthWindow)
			if now.Before(bw.windowEnd) {
				totalBandwidth += bw.bytes
			}
		}
	}

	if count > 0 {
		p.baseline.avgRequestRate = float64(totalRequests) / float64(count)
		p.baseline.avgConnectionRate = float64(totalConnections) / float64(count)
		p.baseline.avgBandwidth = float64(totalBandwidth) / float64(count)
	}
	p.baseline.lastUpdated = now
}

// ---- Cleanup ----

func (p *ddosPolicy) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.cleanupMaps()
			atomic.StoreInt64(&p.lastCleanupNano, time.Now().UnixNano())
		}
	}
}

func (p *ddosPolicy) cleanupMaps() {
	now := time.Now()
	for _, ip := range p.blockedIPs.snapshot() {
		if val, exists := p.blockedIPs.get(ip); exists {
			bi := val.(*blockInfo)
			if now.After(bi.blockedUntil) {
				p.blockedIPs.delete(ip)
				p.attackHistory.delete(ip)
			}
		}
	}
	for _, ip := range p.challengeIPs.snapshot() {
		if val, exists := p.challengeIPs.get(ip); exists {
			ci := val.(*challengeInfo)
			if now.After(ci.expiresAt) {
				p.challengeIPs.delete(ip)
			}
		}
	}
	for _, ip := range p.requestCounts.snapshot() {
		if val, exists := p.requestCounts.get(ip); exists {
			rw := val.(*requestWindow)
			if now.After(rw.windowEnd) {
				p.requestCounts.delete(ip)
			}
		}
	}
	for _, ip := range p.connectionCounts.snapshot() {
		if val, exists := p.connectionCounts.get(ip); exists {
			cw := val.(*requestWindow)
			if now.After(cw.windowEnd) {
				p.connectionCounts.delete(ip)
			}
		}
	}
	for _, ip := range p.bandwidthCounts.snapshot() {
		if val, exists := p.bandwidthCounts.get(ip); exists {
			bw := val.(*bandwidthWindow)
			if now.After(bw.windowEnd) {
				p.bandwidthCounts.delete(ip)
			}
		}
	}
	cutoff := now.Add(-time.Hour)
	for _, ip := range p.attackHistory.snapshot() {
		if val, exists := p.attackHistory.get(ip); exists {
			attacks := val.([]time.Time)
			filtered := make([]time.Time, 0, len(attacks))
			for _, t := range attacks {
				if t.After(cutoff) {
					filtered = append(filtered, t)
				}
			}
			if len(filtered) == 0 {
				p.attackHistory.delete(ip)
			} else {
				p.attackHistory.set(ip, filtered)
			}
		}
	}
}

func (p *ddosPolicy) cleanupLocked() {
	now := time.Now()
	for _, ip := range p.blockedIPs.snapshot() {
		if val, exists := p.blockedIPs.get(ip); exists {
			bi := val.(*blockInfo)
			if now.After(bi.blockedUntil) {
				p.blockedIPs.delete(ip)
				p.attackHistory.delete(ip)
			}
		}
	}
	for _, ip := range p.challengeIPs.snapshot() {
		if val, exists := p.challengeIPs.get(ip); exists {
			ci := val.(*challengeInfo)
			if now.After(ci.expiresAt) {
				p.challengeIPs.delete(ip)
			}
		}
	}
	for _, ip := range p.requestCounts.snapshot() {
		if val, exists := p.requestCounts.get(ip); exists {
			rw := val.(*requestWindow)
			if now.After(rw.windowEnd) {
				p.requestCounts.delete(ip)
			}
		}
	}
	for _, ip := range p.connectionCounts.snapshot() {
		if val, exists := p.connectionCounts.get(ip); exists {
			cw := val.(*requestWindow)
			if now.After(cw.windowEnd) {
				p.connectionCounts.delete(ip)
			}
		}
	}
	for _, ip := range p.bandwidthCounts.snapshot() {
		if val, exists := p.bandwidthCounts.get(ip); exists {
			bw := val.(*bandwidthWindow)
			if now.After(bw.windowEnd) {
				p.bandwidthCounts.delete(ip)
			}
		}
	}
	cutoff := now.Add(-time.Hour)
	for _, ip := range p.attackHistory.snapshot() {
		if val, exists := p.attackHistory.get(ip); exists {
			attacks := val.([]time.Time)
			filtered := make([]time.Time, 0, len(attacks))
			for _, t := range attacks {
				if t.After(cutoff) {
					filtered = append(filtered, t)
				}
			}
			if len(filtered) == 0 {
				p.attackHistory.delete(ip)
			} else {
				p.attackHistory.set(ip, filtered)
			}
		}
	}
}

// ---- Standalone helpers ----

func verifyProofOfWork(challenge, nonce string, difficulty int) bool {
	hash := sha256.Sum256([]byte(challenge + nonce))
	hashHex := hex.EncodeToString(hash[:])
	if len(hashHex) < difficulty {
		return false
	}
	for i := 0; i < difficulty; i++ {
		if hashHex[i] != '0' {
			return false
		}
	}
	return true
}

func getCAPTCHAChallengeHTML(captcha *CAPTCHAConfig) string {
	switch captcha.Provider {
	case "hcaptcha":
		return fmt.Sprintf(`<!DOCTYPE html><html><head><title>Security Challenge</title></head><body><h1>Security Challenge</h1><p>Please complete the CAPTCHA to continue:</p><div class="h-captcha" data-sitekey="%s"></div><script src="https://js.hcaptcha.com/1/api.js" async defer></script></body></html>`, captcha.SiteKey)
	case "recaptcha":
		return fmt.Sprintf(`<!DOCTYPE html><html><head><title>Security Challenge</title></head><body><h1>Security Challenge</h1><p>Please complete the CAPTCHA to continue:</p><div class="g-recaptcha" data-sitekey="%s"></div><script src="https://www.google.com/recaptcha/api.js" async defer></script></body></html>`, captcha.SiteKey)
	case "turnstile":
		return fmt.Sprintf(`<!DOCTYPE html><html><head><title>Security Challenge</title></head><body><h1>Security Challenge</h1><p>Please complete the challenge to continue:</p><div class="cf-turnstile" data-sitekey="%s"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script></body></html>`, captcha.SiteKey)
	default:
		return `<!DOCTYPE html><html><head><title>Security Challenge</title></head><body><h1>Security Challenge Required</h1><p>Please contact support if you believe this is an error.</p></body></html>`
	}
}

func verifyCAPTCHA(token, clientIP string, captcha *CAPTCHAConfig) bool {
	if captcha == nil || captcha.SecretKey == "" {
		return false
	}
	verifyURL := captcha.VerifyURL
	if verifyURL == "" {
		switch captcha.Provider {
		case "hcaptcha":
			verifyURL = "https://hcaptcha.com/siteverify"
		case "recaptcha":
			verifyURL = "https://www.google.com/recaptcha/api/siteverify"
		case "turnstile":
			verifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
		default:
			return false
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data := url.Values{}
	data.Set("secret", captcha.SecretKey)
	data.Set("response", token)
	if clientIP != "" {
		data.Set("remoteip", clientIP)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", verifyURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result.Success
}

func parseBandwidthThreshold(threshold string) int64 {
	if threshold == "" {
		return 0
	}
	threshold = strings.ToUpper(threshold)
	multiplier := int64(1)
	if strings.HasSuffix(threshold, "KB") {
		multiplier = 1024
		threshold = strings.TrimSuffix(threshold, "KB")
	} else if strings.HasSuffix(threshold, "MB") {
		multiplier = 1024 * 1024
		threshold = strings.TrimSuffix(threshold, "MB")
	} else if strings.HasSuffix(threshold, "GB") {
		multiplier = 1024 * 1024 * 1024
		threshold = strings.TrimSuffix(threshold, "GB")
	}
	var value int64
	if _, err := fmt.Sscanf(threshold, "%d", &value); err != nil {
		return 0
	}
	return value * multiplier
}

func createErrorResponse(statusCode int, message string) *http.Response {
	body := strings.NewReader(message)
	resp := &http.Response{
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		StatusCode: statusCode,
		Body:       io.NopCloser(body),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Content-Length", strconv.Itoa(len(message)))
	return resp
}

func createJSONErrorResponse(statusCode int, jsonBody string) *http.Response {
	body := strings.NewReader(jsonBody)
	resp := &http.Response{
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		StatusCode: statusCode,
		Body:       io.NopCloser(body),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(jsonBody)))
	return resp
}

func getClientIPFromRequest(req *http.Request) string {
	if req.RemoteAddr != "" {
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			return host
		}
		return req.RemoteAddr
	}
	return ""
}

// ---- LRU map ----

type lruMap struct {
	data    map[string]interface{}
	order   *list.List
	index   map[string]*list.Element
	maxSize int
	mu      sync.RWMutex
}

func newLRUMap(maxSize int) *lruMap {
	return &lruMap{
		data:    make(map[string]interface{}),
		order:   list.New(),
		index:   make(map[string]*list.Element),
		maxSize: maxSize,
	}
}

func (lru *lruMap) set(key string, value interface{}) {
	lru.mu.Lock()
	defer lru.mu.Unlock()
	if elem, exists := lru.index[key]; exists {
		lru.order.MoveToFront(elem)
		lru.data[key] = value
		return
	}
	if len(lru.data) >= lru.maxSize {
		lru.evictOldest()
	}
	elem := lru.order.PushFront(key)
	lru.index[key] = elem
	lru.data[key] = value
}

// get retrieves a value and promotes it to the front of the LRU list.
// This prevents actively-accessed entries (e.g., blocked IPs still being checked)
// from being evicted while they are still relevant.
func (lru *lruMap) get(key string) (interface{}, bool) {
	lru.mu.Lock()
	defer lru.mu.Unlock()
	val, exists := lru.data[key]
	if exists {
		if elem, ok := lru.index[key]; ok {
			lru.order.MoveToFront(elem)
		}
	}
	return val, exists
}

func (lru *lruMap) getAndUpdate(key string) (interface{}, bool) {
	lru.mu.Lock()
	defer lru.mu.Unlock()
	if elem, exists := lru.index[key]; exists {
		lru.order.MoveToFront(elem)
		return lru.data[key], true
	}
	return nil, false
}

func (lru *lruMap) delete(key string) {
	lru.mu.Lock()
	defer lru.mu.Unlock()
	if elem, exists := lru.index[key]; exists {
		lru.order.Remove(elem)
		delete(lru.index, key)
		delete(lru.data, key)
	}
}

func (lru *lruMap) snapshot() []string {
	lru.mu.RLock()
	defer lru.mu.RUnlock()
	result := make([]string, 0, len(lru.data))
	for key := range lru.data {
		result = append(result, key)
	}
	return result
}

func (lru *lruMap) evictOldest() {
	if lru.order.Len() == 0 {
		return
	}
	elem := lru.order.Back()
	if elem == nil {
		return
	}
	key := elem.Value.(string)
	lru.order.Remove(elem)
	delete(lru.index, key)
	delete(lru.data, key)
}
