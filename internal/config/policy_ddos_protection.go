// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/soapbucket/sbproxy/internal/config/callback"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// lruMap implements a bounded LRU map to prevent OOM from unbounded entries
type lruMap struct {
	data     map[string]interface{}
	order    *list.List
	index    map[string]*list.Element
	maxSize  int
	mu       sync.RWMutex
}

// newLRUMap creates a new bounded LRU map
func newLRUMap(maxSize int) *lruMap {
	return &lruMap{
		data:    make(map[string]interface{}),
		order:   list.New(),
		index:   make(map[string]*list.Element),
		maxSize: maxSize,
	}
}

// set stores a value in the LRU map, evicting oldest if at capacity
func (lru *lruMap) set(key string, value interface{}) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	if elem, exists := lru.index[key]; exists {
		// Update existing
		lru.order.MoveToFront(elem)
		lru.data[key] = value
		return
	}

	// Add new
	if len(lru.data) >= lru.maxSize {
		lru.evictOldest()
	}

	elem := lru.order.PushFront(key)
	lru.index[key] = elem
	lru.data[key] = value
}

// get retrieves a value from the LRU map
func (lru *lruMap) get(key string) (interface{}, bool) {
	lru.mu.RLock()
	defer lru.mu.RUnlock()

	val, exists := lru.data[key]
	return val, exists
}

// getAndUpdate retrieves a value and marks it as recently used
func (lru *lruMap) getAndUpdate(key string) (interface{}, bool) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	if elem, exists := lru.index[key]; exists {
		lru.order.MoveToFront(elem)
		val := lru.data[key]
		return val, true
	}
	return nil, false
}

// delete removes a key from the LRU map
func (lru *lruMap) delete(key string) {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	if elem, exists := lru.index[key]; exists {
		lru.order.Remove(elem)
		delete(lru.index, key)
		delete(lru.data, key)
	}
}

// evictOldest removes the least recently used entry
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

// snapshot returns all keys in the map under read lock for safe iteration
func (lru *lruMap) snapshot() []string {
	lru.mu.RLock()
	defer lru.mu.RUnlock()

	result := make([]string, 0, len(lru.data))
	for key := range lru.data {
		result = append(result, key)
	}
	return result
}

// clear removes all entries
func (lru *lruMap) clear() {
	lru.mu.Lock()
	defer lru.mu.Unlock()

	lru.data = make(map[string]interface{})
	lru.order = list.New()
	lru.index = make(map[string]*list.Element)
}

func init() {
	policyLoaderFns[PolicyTypeDDoSProtection] = NewDDoSProtectionPolicy
}

// DDoSProtectionPolicyConfig implements PolicyConfig for DDoS protection
type DDoSProtectionPolicyConfig struct {
	DDoSProtectionPolicy

	// Internal
	config           *Config
	requestCounts    *lruMap // Bounded to 50k entries
	connectionCounts *lruMap // Bounded to 50k entries
	bandwidthCounts  *lruMap // Bounded to 50k entries
	blockedIPs       *lruMap // Bounded to 100k entries
	challengeIPs     *lruMap // Bounded to 100k entries
	attackHistory    *lruMap // Bounded to 10k entries
	baseline         *trafficBaseline
	lastCleanup      time.Time
	customHTMLCallback *callback.Callback // Deferred initialization to avoid import cycle
	stateStore       PolicyStateStore     // External state store for distributed deployments (nil = local only)
	mu               sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
}

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

// NewDDoSProtectionPolicy creates a new DDoS protection policy config
func NewDDoSProtectionPolicy(data []byte) (PolicyConfig, error) {
	cfg := &DDoSProtectionPolicyConfig{
		requestCounts:    newLRUMap(50000),    // 50k IPs max
		connectionCounts: newLRUMap(50000),    // 50k IPs max
		bandwidthCounts:  newLRUMap(50000),    // 50k IPs max
		blockedIPs:       newLRUMap(100000),   // 100k IPs max
		challengeIPs:     newLRUMap(100000),   // 100k IPs max
		attackHistory:    newLRUMap(10000),    // 10k IPs max
		baseline:         &trafficBaseline{},
		lastCleanup:      time.Now(),
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Set defaults
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
	}

	if cfg.Detection != nil {
		if cfg.Detection.ThresholdMultiplier == 0 {
			cfg.Detection.ThresholdMultiplier = 2.0
		}
		if cfg.Detection.BaselineWindow == "" {
			cfg.Detection.BaselineWindow = "1h"
		}
	}

	// Unmarshal custom HTML callback if present (deferred to avoid import cycle in types.go)
	if len(cfg.Mitigation.CustomHTMLCallback) > 0 {
		var cb callback.Callback
		if err := json.Unmarshal(cfg.Mitigation.CustomHTMLCallback, &cb); err == nil {
			cfg.customHTMLCallback = &cb
		}
	}

	return cfg, nil
}

// SetStateStore sets an external policy state store for distributed deployments.
// When set, blocked IPs and challenge state are persisted externally so that
// all proxy instances share the same view. If not called, all state remains
// local to the in-memory lruMaps (the default, backwards-compatible behavior).
func (p *DDoSProtectionPolicyConfig) SetStateStore(store PolicyStateStore) {
	p.stateStore = store
}

// Init initializes the policy config
func (p *DDoSProtectionPolicyConfig) Init(config *Config) error {
	p.config = config
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Start background goroutines
	go p.cleanup()
	if p.Detection != nil && p.Detection.AdaptiveThresholds {
		go p.updateBaseline()
	}

	return nil
}

// cleanup periodically cleans up expired entries.
// Each lruMap has its own internal mutex, so we do not hold the outer struct
// mutex during the full iteration. Instead we perform independent cleanup
// passes per map, only acquiring p.mu briefly to update lastCleanup.
func (p *DDoSProtectionPolicyConfig) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.cleanupMaps()
			p.mu.Lock()
			p.lastCleanup = time.Now()
			p.mu.Unlock()
		}
	}
}

// updateBaseline periodically updates traffic baseline for adaptive thresholds
func (p *DDoSProtectionPolicyConfig) updateBaseline() {
	if p.Detection == nil || !p.Detection.AdaptiveThresholds {
		return
	}

	baselineWindow, err := time.ParseDuration(p.Detection.BaselineWindow)
	if err != nil {
		baselineWindow = time.Hour
	}

	ticker := time.NewTicker(baselineWindow / 4) // Update 4 times per baseline window
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

// Apply implements the middleware pattern for DDoS protection
func (p *DDoSProtectionPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := GetClientIPFromRequest(r)
		if clientIP == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if IP is currently blocked
		if p.isBlocked(clientIP) {
			logging.LogSecurityEvent(r.Context(), logging.SecurityEventDDoSAttack, logging.SeverityHigh, "ddos_check", "blocked",
				zap.String("ip", clientIP),
				zap.String("reason", "ip_blocked"),
			)
			reqctx.RecordPolicyViolation(r.Context(), "ddos", "IP temporarily blocked due to suspicious activity")
			http.Error(w, "IP temporarily blocked due to suspicious activity", http.StatusTooManyRequests)
			return
		}

		// Check if IP needs to complete a challenge
		if p.needsChallenge(clientIP) {
			resp := p.handleChallenge(r, clientIP)
			w.WriteHeader(resp.StatusCode)
			if resp.Body != nil {
				defer resp.Body.Close()
				var buf []byte
				buf, _ = io.ReadAll(resp.Body)
				w.Write(buf)
			}
			return
		}

		// Detect potential attacks
		if p.Detection != nil {
			attack := p.detectAttack(clientIP, r)
			if attack != nil {
				origin := "unknown"
				if p.config != nil {
					origin = p.config.ID
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

		// All checks passed, continue to next handler
		next.ServeHTTP(w, r)
	})
}

func (p *DDoSProtectionPolicyConfig) detectAttack(clientIP string, req *http.Request) *attackInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	window := p.getDetectionWindow()

	// Clean up old data
	if now.Sub(p.lastCleanup) > window {
		p.cleanupLocked()
		p.lastCleanup = now
	}

	// Get thresholds (adaptive or static)
	requestThreshold := p.getRequestThreshold()
	connectionThreshold := p.getConnectionThreshold()
	bandwidthThreshold := p.getBandwidthThreshold()

	// Check request rate
	if requestThreshold > 0 {
		// Use external state store for distributed counting when available
		if p.stateStore != nil {
			storeKey := "reqcount:" + clientIP
			count, err := p.stateStore.Increment(p.ctx, storeKey, window)
			if err == nil && count > int64(requestThreshold) {
				return &attackInfo{
					Type:       "request_rate",
					IP:         clientIP,
					Count:      int(count),
					Threshold:  requestThreshold,
					DetectedAt: now,
				}
			}
		} else {
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
	}

	// Check connection rate
	if connectionThreshold > 0 {
		if p.stateStore != nil {
			storeKey := "conncount:" + clientIP
			count, err := p.stateStore.Increment(p.ctx, storeKey, window)
			if err == nil && count > int64(connectionThreshold) {
				return &attackInfo{
					Type:       "connection_rate",
					IP:         clientIP,
					Count:      int(count),
					Threshold:  connectionThreshold,
					DetectedAt: now,
				}
			}
		} else {
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
	}

	// Check bandwidth
	if bandwidthThreshold > 0 {
		contentLength := int64(req.ContentLength)
		if contentLength < 0 {
			contentLength = 0
		}

		if p.stateStore != nil {
			// For bandwidth, we increment by content length. The Increment method
			// adds 1 each time, so we call it contentLength times conceptually.
			// In practice, we use Set with the accumulated value from Get.
			storeKey := "bwcount:" + clientIP
			data, err := p.stateStore.Get(p.ctx, storeKey)
			var currentBytes int64
			if err == nil && data != nil {
				fmt.Sscanf(string(data), "%d", &currentBytes)
			}
			currentBytes += contentLength
			_ = p.stateStore.Set(p.ctx, storeKey, []byte(fmt.Sprintf("%d", currentBytes)), window)
			if currentBytes > bandwidthThreshold {
				return &attackInfo{
					Type:       "bandwidth",
					IP:         clientIP,
					Count:      int(currentBytes),
					Threshold:  int(bandwidthThreshold),
					DetectedAt: now,
				}
			}
		} else {
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
	}

	return nil
}

// getRequestThreshold returns the request rate threshold (adaptive or static)
func (p *DDoSProtectionPolicyConfig) getRequestThreshold() int {
	if p.Detection == nil {
		return 0
	}
	if p.Detection.AdaptiveThresholds && p.baseline.avgRequestRate > 0 {
		return int(p.baseline.avgRequestRate * p.Detection.ThresholdMultiplier)
	}
	return p.Detection.RequestRateThreshold
}

// getConnectionThreshold returns the connection rate threshold (adaptive or static)
func (p *DDoSProtectionPolicyConfig) getConnectionThreshold() int {
	if p.Detection == nil {
		return 0
	}
	if p.Detection.AdaptiveThresholds && p.baseline.avgConnectionRate > 0 {
		return int(p.baseline.avgConnectionRate * p.Detection.ThresholdMultiplier)
	}
	return p.Detection.ConnectionRateThreshold
}

// getBandwidthThreshold returns the bandwidth threshold (adaptive or static)
func (p *DDoSProtectionPolicyConfig) getBandwidthThreshold() int64 {
	if p.Detection == nil {
		return 0
	}
	if p.Detection.BandwidthThreshold == "" {
		return 0
	}
	threshold := p.parseBandwidthThreshold(p.Detection.BandwidthThreshold)
	if p.Detection.AdaptiveThresholds && p.baseline.avgBandwidth > 0 {
		return int64(p.baseline.avgBandwidth * p.Detection.ThresholdMultiplier)
	}
	return threshold
}

// calculateBaseline calculates traffic baseline for adaptive thresholds
func (p *DDoSProtectionPolicyConfig) calculateBaseline() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	totalRequests := 0
	totalConnections := 0
	var totalBandwidth int64
	count := 0

	// Calculate averages from current windows
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

func (p *DDoSProtectionPolicyConfig) handleAttack(attack *attackInfo) {
	if p.Mitigation == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Track attack history
	var attacks []time.Time
	if val, exists := p.attackHistory.get(attack.IP); exists {
		attacks = val.([]time.Time)
	}
	attacks = append(attacks, attack.DetectedAt)

	// Clean old attacks from history (keep last hour)
	cutoff := time.Now().Add(-time.Hour)
	filtered := make([]time.Time, 0, len(attacks))
	for _, t := range attacks {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	p.attackHistory.set(attack.IP, filtered)

	attackCount := len(filtered)

	// Auto-block if configured and threshold reached
	if p.Mitigation.AutoBlock && attackCount >= p.Mitigation.BlockAfterAttacks {
		blockDuration, err := time.ParseDuration(p.Mitigation.BlockDuration)
		if err != nil {
			blockDuration = time.Hour // Default
		}

		bi := &blockInfo{
			blockedUntil: time.Now().Add(blockDuration),
			attackCount:  attackCount,
		}
		p.blockedIPs.set(attack.IP, bi)

		// Persist to external state store for cross-instance visibility
		if p.stateStore != nil {
			storeKey := "blocked:" + attack.IP
			// Value is the attack count as a simple marker; TTL handles expiration
			_ = p.stateStore.Set(p.ctx, storeKey, []byte(fmt.Sprintf("%d", attackCount)), blockDuration)
		}
		return
	}

	// Otherwise, issue challenge if configured
	if p.Mitigation.ChallengeResponse {
		challengeDuration := 5 * time.Minute
		if p.Mitigation.ProofOfWork != nil && p.Mitigation.ProofOfWork.Timeout != "" {
			if d, err := time.ParseDuration(p.Mitigation.ProofOfWork.Timeout); err == nil {
				challengeDuration = d
			}
		}

		challengeInfo := &challengeInfo{
			challengeType: p.Mitigation.ChallengeType,
			expiresAt:     time.Now().Add(challengeDuration),
		}

		// Generate challenge data based on type
		switch p.Mitigation.ChallengeType {
		case "proof_of_work":
			challengeInfo.challengeData = p.generateProofOfWorkChallenge(attack.IP)
		case "javascript":
			challengeInfo.challengeData = p.generateJavaScriptChallenge(attack.IP)
		case "captcha":
			challengeInfo.challengeData = p.generateCAPTCHAChallenge(attack.IP)
		default:
			challengeInfo.challengeData = fmt.Sprintf("challenge_%s", attack.IP)
		}

		p.challengeIPs.set(attack.IP, challengeInfo)

		// Persist challenge state to external store for cross-instance visibility
		if p.stateStore != nil {
			storeKey := "challenge:" + attack.IP
			_ = p.stateStore.Set(p.ctx, storeKey, []byte(challengeInfo.challengeType), challengeDuration)
		}
	}
}

func (p *DDoSProtectionPolicyConfig) handleChallenge(req *http.Request, clientIP string) *http.Response {
	if p.Mitigation == nil || !p.Mitigation.ChallengeResponse {
		return createErrorResponse(http.StatusTooManyRequests,
			"Challenge verification failed")
	}

	p.mu.RLock()
	val, exists := p.challengeIPs.get(clientIP)
	p.mu.RUnlock()

	if !exists {
		return createErrorResponse(http.StatusTooManyRequests,
			"Challenge not found")
	}

	challengeInfo := val.(*challengeInfo)

	// Handle different challenge types
	switch challengeInfo.challengeType {
	case "proof_of_work":
		return p.handleProofOfWorkChallenge(req, clientIP, challengeInfo)
	case "javascript":
		return p.handleJavaScriptChallenge(req, clientIP, challengeInfo)
	case "captcha":
		return p.handleCAPTCHAChallenge(req, clientIP, challengeInfo)
	default:
		return p.handleHeaderChallenge(req, clientIP, challengeInfo)
	}
}

// handleHeaderChallenge handles basic header-based challenge
func (p *DDoSProtectionPolicyConfig) handleHeaderChallenge(req *http.Request, clientIP string, challengeInfo *challengeInfo) *http.Response {
	challengeHeader := req.Header.Get("X-Challenge-Response")
	if challengeHeader == "" {
		// Try to get custom HTML from callback first
		html := p.getCustomChallengeHTML(req, challengeInfo, "header")
		if html != "" {
			// Return custom HTML
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(html)),
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html")
			return resp
		}
		// Fall back to JSON response
		response := fmt.Sprintf(`{
			"error": "challenge_required",
			"message": "Please complete the challenge to continue",
			"challenge": "%s",
			"instructions": "Add X-Challenge-Response header with the challenge value"
		}`, challengeInfo.challengeData)
		return createJSONErrorResponse(http.StatusTooManyRequests, response)
	}

	if p.verifyChallenge(clientIP, challengeHeader) {
		p.mu.Lock()
		p.challengeIPs.delete(clientIP)
		p.mu.Unlock()
		return nil // Challenge passed
	}

	return createErrorResponse(http.StatusTooManyRequests,
		"Challenge verification failed")
}

// handleProofOfWorkChallenge handles proof-of-work challenge
func (p *DDoSProtectionPolicyConfig) handleProofOfWorkChallenge(req *http.Request, clientIP string, challengeInfo *challengeInfo) *http.Response {
	if p.Mitigation.ProofOfWork == nil || !p.Mitigation.ProofOfWork.Enabled {
		return createErrorResponse(http.StatusTooManyRequests,
			"Proof-of-work challenge not configured")
	}

	powHeader := req.Header.Get(p.Mitigation.ProofOfWork.HeaderName)
	if powHeader == "" {
		// Try to get custom HTML from callback first
		html := p.getCustomChallengeHTML(req, challengeInfo, "proof_of_work")
		if html != "" {
			// Return custom HTML
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(html)),
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html")
			return resp
		}
		// Fall back to JSON response
		difficulty := p.Mitigation.ProofOfWork.Difficulty
		response := fmt.Sprintf(`{
			"error": "proof_of_work_required",
			"message": "Please complete the proof-of-work challenge",
			"challenge": "%s",
			"difficulty": %d,
			"instructions": "Find a nonce such that SHA256(challenge + nonce) has %d leading zeros. Submit the nonce in the %s header."
		}`, challengeInfo.challengeData, difficulty, difficulty, p.Mitigation.ProofOfWork.HeaderName)
		return createJSONErrorResponse(http.StatusTooManyRequests, response)
	}

	// Verify proof-of-work
	if p.verifyProofOfWork(challengeInfo.challengeData, powHeader, p.Mitigation.ProofOfWork.Difficulty) {
		p.mu.Lock()
		p.challengeIPs.delete(clientIP)
		p.mu.Unlock()
		return nil // Challenge passed
	}

	return createErrorResponse(http.StatusTooManyRequests,
		"Proof-of-work verification failed")
}

// handleJavaScriptChallenge handles JavaScript challenge
func (p *DDoSProtectionPolicyConfig) handleJavaScriptChallenge(req *http.Request, clientIP string, challengeInfo *challengeInfo) *http.Response {
	if p.Mitigation.JavaScriptChallenge == nil || !p.Mitigation.JavaScriptChallenge.Enabled {
		return createErrorResponse(http.StatusTooManyRequests,
			"JavaScript challenge not configured")
	}

	jsHeader := req.Header.Get(p.Mitigation.JavaScriptChallenge.HeaderName)
	if jsHeader == "" {
		// Try to get custom HTML from callback first
		htmlContent := p.getCustomChallengeHTML(req, challengeInfo, "javascript")
		if htmlContent == "" {
			// Fall back to default HTML
			jsScript := p.getJavaScriptChallengeScript(challengeInfo.challengeData)
			htmlContent = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Security Challenge</title></head>
<body>
	<h1>Security Challenge</h1>
	<p>Please wait while we verify your browser...</p>
	<script>%s</script>
</body>
</html>`, html.EscapeString(jsScript))
		}
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(htmlContent)),
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")
		return resp
	}

	// Verify JavaScript challenge response
	if p.verifyJavaScriptChallenge(challengeInfo.challengeData, jsHeader) {
		p.mu.Lock()
		p.challengeIPs.delete(clientIP)
		p.mu.Unlock()
		return nil // Challenge passed
	}

	return createErrorResponse(http.StatusTooManyRequests,
		"JavaScript challenge verification failed")
}

// handleCAPTCHAChallenge handles CAPTCHA challenge
func (p *DDoSProtectionPolicyConfig) handleCAPTCHAChallenge(req *http.Request, clientIP string, challengeInfo *challengeInfo) *http.Response {
	if p.Mitigation.CAPTCHA == nil || !p.Mitigation.CAPTCHA.Enabled {
		return createErrorResponse(http.StatusTooManyRequests,
			"CAPTCHA challenge not configured")
	}

	captchaToken := req.Header.Get("X-CAPTCHA-Token")
	if captchaToken == "" {
		// Try to get custom HTML from callback first
		html := p.getCustomChallengeHTML(req, challengeInfo, "captcha")
		if html == "" {
			// Fall back to default HTML
			html = p.getCAPTCHAChallengeHTML(p.Mitigation.CAPTCHA)
		}
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(html)),
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")
		return resp
	}

	// Verify CAPTCHA
	if p.verifyCAPTCHA(captchaToken, clientIP) {
		p.mu.Lock()
		p.challengeIPs.delete(clientIP)
		p.mu.Unlock()
		return nil // Challenge passed
	}

	return createErrorResponse(http.StatusTooManyRequests,
		"CAPTCHA verification failed")
}

func (p *DDoSProtectionPolicyConfig) verifyChallenge(clientIP, response string) bool {
	expected := fmt.Sprintf("challenge_%s", clientIP)
	return response == expected
}

// generateProofOfWorkChallenge generates a proof-of-work challenge
func (p *DDoSProtectionPolicyConfig) generateProofOfWorkChallenge(clientIP string) string {
	return fmt.Sprintf("pow_%s_%d", clientIP, time.Now().Unix())
}

// verifyProofOfWork verifies proof-of-work solution
func (p *DDoSProtectionPolicyConfig) verifyProofOfWork(challenge, nonce string, difficulty int) bool {
	// Compute SHA256(challenge + nonce)
	hash := sha256.Sum256([]byte(challenge + nonce))
	hashHex := hex.EncodeToString(hash[:])

	// Check if hash has required number of leading zeros
	requiredZeros := difficulty
	if len(hashHex) < requiredZeros {
		return false
	}

	for i := 0; i < requiredZeros; i++ {
		if hashHex[i] != '0' {
			return false
		}
	}

	return true
}

// generateJavaScriptChallenge generates a JavaScript challenge
func (p *DDoSProtectionPolicyConfig) generateJavaScriptChallenge(clientIP string) string {
	return fmt.Sprintf("js_%s_%d", clientIP, time.Now().Unix())
}

// getJavaScriptChallengeScript returns JavaScript code for browser challenge
func (p *DDoSProtectionPolicyConfig) getJavaScriptChallengeScript(challenge string) string {
	return fmt.Sprintf(`
		(function() {
			var challenge = '%s';
			var result = btoa(challenge + '_' + navigator.userAgent + '_' + Date.now());
			var xhr = new XMLHttpRequest();
			xhr.open('POST', window.location.href, true);
			xhr.setRequestHeader('%s', result);
			xhr.onload = function() {
				if (xhr.status === 200) {
					window.location.reload();
				}
			};
			xhr.send();
		})();
	`, challenge, p.Mitigation.JavaScriptChallenge.HeaderName)
}

// verifyJavaScriptChallenge verifies JavaScript challenge response
func (p *DDoSProtectionPolicyConfig) verifyJavaScriptChallenge(challenge, response string) bool {
	// Basic verification - in production, use more sophisticated validation
	return strings.Contains(response, challenge)
}

// generateCAPTCHAChallenge generates a CAPTCHA challenge
func (p *DDoSProtectionPolicyConfig) generateCAPTCHAChallenge(clientIP string) string {
	return fmt.Sprintf("captcha_%s_%d", clientIP, time.Now().Unix())
}

// getCAPTCHAChallengeHTML returns HTML with CAPTCHA widget
func (p *DDoSProtectionPolicyConfig) getCAPTCHAChallengeHTML(captcha *CAPTCHAConfig) string {
	switch captcha.Provider {
	case "hcaptcha":
		return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Security Challenge</title></head>
<body>
	<h1>Security Challenge</h1>
	<p>Please complete the CAPTCHA to continue:</p>
	<div class="h-captcha" data-sitekey="%s"></div>
	<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
</body>
</html>`, captcha.SiteKey)
	case "recaptcha":
		return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Security Challenge</title></head>
<body>
	<h1>Security Challenge</h1>
	<p>Please complete the CAPTCHA to continue:</p>
	<div class="g-recaptcha" data-sitekey="%s"></div>
	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
</body>
</html>`, captcha.SiteKey)
	case "turnstile":
		return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Security Challenge</title></head>
<body>
	<h1>Security Challenge</h1>
	<p>Please complete the challenge to continue:</p>
	<div class="cf-turnstile" data-sitekey="%s"></div>
	<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</body>
</html>`, captcha.SiteKey)
	default:
		return `<!DOCTYPE html>
<html>
<head><title>Security Challenge</title></head>
<body>
	<h1>Security Challenge Required</h1>
	<p>Please contact support if you believe this is an error.</p>
</body>
</html>`
	}
}

// verifyCAPTCHA verifies CAPTCHA token with provider
func (p *DDoSProtectionPolicyConfig) verifyCAPTCHA(token, clientIP string) bool {
	if p.Mitigation.CAPTCHA == nil || p.Mitigation.CAPTCHA.SecretKey == "" {
		return false
	}

	// Determine verification URL
	verifyURL := p.Mitigation.CAPTCHA.VerifyURL
	if verifyURL == "" {
		switch p.Mitigation.CAPTCHA.Provider {
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

	// Verify with provider
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data := url.Values{}
	data.Set("secret", p.Mitigation.CAPTCHA.SecretKey)
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

// getCustomChallengeHTML fetches custom HTML from callback if configured
func (p *DDoSProtectionPolicyConfig) getCustomChallengeHTML(req *http.Request, challengeInfo *challengeInfo, challengeType string) string {
	if p.customHTMLCallback == nil {
		return ""
	}

	// Build callback data with challenge information
	callbackData := map[string]any{
		"challenge_type": challengeType,
		"challenge_data": challengeInfo.challengeData,
		"client_ip":      GetClientIPFromRequest(req),
		"user_agent":     req.UserAgent(),
		"request_path":   req.URL.Path,
		"request_method": req.Method,
	}

	// Add challenge-specific data
	switch challengeType {
	case "proof_of_work":
		if p.Mitigation.ProofOfWork != nil {
			callbackData["difficulty"] = p.Mitigation.ProofOfWork.Difficulty
			callbackData["header_name"] = p.Mitigation.ProofOfWork.HeaderName
			callbackData["timeout"] = p.Mitigation.ProofOfWork.Timeout
		}
	case "javascript":
		if p.Mitigation.JavaScriptChallenge != nil {
			callbackData["header_name"] = p.Mitigation.JavaScriptChallenge.HeaderName
			callbackData["timeout"] = p.Mitigation.JavaScriptChallenge.Timeout
		}
	case "captcha":
		if p.Mitigation.CAPTCHA != nil {
			callbackData["provider"] = p.Mitigation.CAPTCHA.Provider
			callbackData["site_key"] = p.Mitigation.CAPTCHA.SiteKey
		}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()

	// Fetch HTML from callback
	fetchResp, err := p.customHTMLCallback.Fetch(ctx, callbackData)
	if err != nil {
		// Log error but don't fail - fall back to default HTML
		return ""
	}

	// Extract HTML from response body (Body is already []byte)
	if fetchResp != nil && len(fetchResp.Body) > 0 {
		return string(fetchResp.Body)
	}

	return ""
}

func (p *DDoSProtectionPolicyConfig) isBlocked(ip string) bool {
	// Check external state store first (distributed view)
	if p.stateStore != nil {
		storeKey := "blocked:" + ip
		data, err := p.stateStore.Get(p.ctx, storeKey)
		if err == nil && data != nil {
			// Key exists with TTL managed by the store, so the IP is blocked
			return true
		}
	}

	// Fall back to local lruMap
	p.mu.RLock()
	val, exists := p.blockedIPs.get(ip)
	p.mu.RUnlock()

	if !exists {
		return false
	}

	blockInfo := val.(*blockInfo)
	if time.Now().After(blockInfo.blockedUntil) {
		// Block has expired, remove it
		p.mu.Lock()
		p.blockedIPs.delete(ip)
		p.attackHistory.delete(ip)
		p.mu.Unlock()
		return false
	}

	return true
}

func (p *DDoSProtectionPolicyConfig) needsChallenge(ip string) bool {
	// Check external state store for distributed challenge state
	if p.stateStore != nil {
		storeKey := "challenge:" + ip
		data, err := p.stateStore.Get(p.ctx, storeKey)
		if err == nil && data != nil {
			return true
		}
	}

	// Fall back to local lruMap
	p.mu.RLock()
	val, exists := p.challengeIPs.get(ip)
	p.mu.RUnlock()

	if !exists {
		return false
	}

	challengeInfo := val.(*challengeInfo)
	if time.Now().After(challengeInfo.expiresAt) {
		// Challenge has expired
		p.mu.Lock()
		p.challengeIPs.delete(ip)
		p.mu.Unlock()
		return false
	}

	return true
}

func (p *DDoSProtectionPolicyConfig) getDetectionWindow() time.Duration {
	if p.Detection == nil || p.Detection.DetectionWindow == "" {
		return 10 * time.Second
	}

	window, err := time.ParseDuration(p.Detection.DetectionWindow)
	if err != nil {
		return 10 * time.Second
	}
	return window
}

func (p *DDoSProtectionPolicyConfig) parseBandwidthThreshold(threshold string) int64 {
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

// cleanupMaps performs per-map cleanup without holding the outer struct mutex.
// Each lruMap has its own internal lock (mu), so concurrent access to different
// maps does not cause contention. This avoids holding p.mu during potentially
// lengthy map iterations.
func (p *DDoSProtectionPolicyConfig) cleanupMaps() {
	now := time.Now()

	// Each pass is independent; no outer lock needed because each lruMap
	// protects itself with its own sync.RWMutex.

	// Remove expired blocks
	for _, ip := range p.blockedIPs.snapshot() {
		if val, exists := p.blockedIPs.get(ip); exists {
			bi := val.(*blockInfo)
			if now.After(bi.blockedUntil) {
				p.blockedIPs.delete(ip)
				p.attackHistory.delete(ip)
			}
		}
	}

	// Remove expired challenges
	for _, ip := range p.challengeIPs.snapshot() {
		if val, exists := p.challengeIPs.get(ip); exists {
			ci := val.(*challengeInfo)
			if now.After(ci.expiresAt) {
				p.challengeIPs.delete(ip)
			}
		}
	}

	// Clean up expired request windows
	for _, ip := range p.requestCounts.snapshot() {
		if val, exists := p.requestCounts.get(ip); exists {
			rw := val.(*requestWindow)
			if now.After(rw.windowEnd) {
				p.requestCounts.delete(ip)
			}
		}
	}

	// Clean up expired connection windows
	for _, ip := range p.connectionCounts.snapshot() {
		if val, exists := p.connectionCounts.get(ip); exists {
			cw := val.(*requestWindow)
			if now.After(cw.windowEnd) {
				p.connectionCounts.delete(ip)
			}
		}
	}

	// Clean up expired bandwidth windows
	for _, ip := range p.bandwidthCounts.snapshot() {
		if val, exists := p.bandwidthCounts.get(ip); exists {
			bw := val.(*bandwidthWindow)
			if now.After(bw.windowEnd) {
				p.bandwidthCounts.delete(ip)
			}
		}
	}

	// Clean up old attack history (keep last hour)
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

// cleanupLocked performs cleanup. Must be called with p.mu held.
// This is used by detectAttack for inline cleanup during detection passes.
func (p *DDoSProtectionPolicyConfig) cleanupLocked() {
	now := time.Now()

	// Remove expired blocks
	for _, ip := range p.blockedIPs.snapshot() {
		if val, exists := p.blockedIPs.get(ip); exists {
			blockInfo := val.(*blockInfo)
			if now.After(blockInfo.blockedUntil) {
				p.blockedIPs.delete(ip)
				p.attackHistory.delete(ip)
			}
		}
	}

	// Remove expired challenges
	for _, ip := range p.challengeIPs.snapshot() {
		if val, exists := p.challengeIPs.get(ip); exists {
			challengeInfo := val.(*challengeInfo)
			if now.After(challengeInfo.expiresAt) {
				p.challengeIPs.delete(ip)
			}
		}
	}

	// Clean up expired request windows
	for _, ip := range p.requestCounts.snapshot() {
		if val, exists := p.requestCounts.get(ip); exists {
			rw := val.(*requestWindow)
			if now.After(rw.windowEnd) {
				p.requestCounts.delete(ip)
			}
		}
	}

	// Clean up expired connection windows
	for _, ip := range p.connectionCounts.snapshot() {
		if val, exists := p.connectionCounts.get(ip); exists {
			cw := val.(*requestWindow)
			if now.After(cw.windowEnd) {
				p.connectionCounts.delete(ip)
			}
		}
	}

	// Clean up expired bandwidth windows
	for _, ip := range p.bandwidthCounts.snapshot() {
		if val, exists := p.bandwidthCounts.get(ip); exists {
			bw := val.(*bandwidthWindow)
			if now.After(bw.windowEnd) {
				p.bandwidthCounts.delete(ip)
			}
		}
	}

	// Clean up old attack history (keep last hour)
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

type attackInfo struct {
	Type       string
	IP         string
	Count      int
	Threshold  int
	DetectedAt time.Time
}

// createErrorResponse creates an HTTP response with a plain text error message.
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

// createJSONErrorResponse creates an HTTP response with JSON body
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

