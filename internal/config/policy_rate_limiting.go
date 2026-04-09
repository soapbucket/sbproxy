// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
//
// Rate Limiting: In-Memory vs. Distributed
//
// The in-memory rate limiter (counters map) is per-process only. Each proxy instance
// maintains its own independent counters, so a client can exceed the configured limit
// by a factor of N where N is the number of proxy instances. For accurate rate limiting
// across multiple instances, configure a Redis-backed cache (L2 cache) so the advanced
// rate limiting path (applyRateLimit with sliding_window/token_bucket/leaky_bucket) is
// used instead. The in-memory fallback is suitable for single-instance deployments or
// as a best-effort safety net when Redis is unavailable.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/request/ratelimit"
)

func init() {
	policyLoaderFns[PolicyTypeRateLimiting] = NewRateLimitingPolicy
}

// RateLimitingPolicyConfig implements PolicyConfig for rate limiting
type RateLimitingPolicyConfig struct {
	RateLimitingPolicy

	// Internal
	config    *Config
	whitelist []*net.IPNet
	blacklist []*net.IPNet
	mu        sync.RWMutex
	// In-memory counters (for simple implementation)
	// In production, this should use Redis or similar
	counters map[string]*rateLimitCounters
	ctx      context.Context
	cancel   context.CancelFunc

	// Throttle queue - buffered channel acts as the queue
	throttleQueue chan struct{}
}

// maxRateLimitCounters is the maximum number of rate limit counter entries
// to prevent unbounded memory growth from unique client IPs.
const maxRateLimitCounters = 100000

type rateLimitCounters struct {
	firstSeen   time.Time
	minuteCount int
	hourCount   int
	dayCount    int
	lastMinute  time.Time
	lastHour    time.Time
	lastDay     time.Time
	lastAccess  time.Time

	// Quota tracking
	quotaDailyCount   int
	quotaMonthlyCount int
	quotaDailyReset   time.Time
	quotaMonthlyReset time.Time
}

// NewRateLimitingPolicy creates a new rate limiting policy config
func NewRateLimitingPolicy(data []byte) (PolicyConfig, error) {
	cfg := &RateLimitingPolicyConfig{
		counters: make(map[string]*rateLimitCounters),
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Parse whitelist
	cfg.whitelist = parseIPList(cfg.Whitelist)
	cfg.blacklist = parseIPList(cfg.Blacklist)

	return cfg, nil
}

// Init initializes the policy config
func (p *RateLimitingPolicyConfig) Init(config *Config) error {
	p.config = config
	// Create context for cleanup goroutine
	p.ctx, p.cancel = context.WithCancel(context.Background())
	// Start cleanup goroutine
	go p.cleanup()

	// Initialize throttle queue if enabled
	if p.Throttle != nil && p.Throttle.Enabled {
		maxQueue := p.Throttle.MaxQueue
		if maxQueue <= 0 {
			maxQueue = 100
		}
		p.throttleQueue = make(chan struct{}, maxQueue)
	}

	// Warn if no external cache is available. In-memory counters are per-instance only,
	// so rate limits will not be enforced accurately across multiple proxy instances.
	// Configure a Redis-backed L2 cache for distributed rate limiting.
	slog.Warn("rate limiter initialized in per-instance in-memory mode; configure Redis (L2 cache) for accurate multi-instance rate limiting",
		"config_id", config.ID)

	return nil
}

// Shutdown stops the cleanup goroutine
func (p *RateLimitingPolicyConfig) Shutdown() {
	if p.cancel != nil {
		p.cancel()
	}
}

// Apply implements the middleware pattern for rate limiting
func (p *RateLimitingPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := GetClientIPFromRequest(r)
		if clientIP == "" {
			// Can't rate limit without IP, allow request
			next.ServeHTTP(w, r)
			return
		}

		parsedIP := net.ParseIP(clientIP)
		if parsedIP == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Check whitelist
		if len(p.whitelist) > 0 {
			for _, ipNet := range p.whitelist {
				if ipNet.Contains(parsedIP) {
					// Whitelisted, no rate limit
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// Check blacklist
		if len(p.blacklist) > 0 {
			for _, ipNet := range p.blacklist {
				if ipNet.Contains(parsedIP) {
					reqctx.RecordPolicyViolation(r.Context(), "rate_limit", "IP address is blacklisted")
					http.Error(w, "IP address is blacklisted", http.StatusTooManyRequests)
					return
				}
			}
		}

		// Extract endpoint path
		endpoint := r.URL.Path
		if endpoint == "" {
			endpoint = "/"
		}

		// Check quota limits before rate limiting
		if p.Quota != nil && (p.Quota.Daily > 0 || p.Quota.Monthly > 0) {
			if !p.checkQuota(w, r, clientIP, endpoint) {
				return
			}
		}

		// Get limits for this IP and endpoint
		limits, endpointPattern := p.getLimitsForRequest(clientIP, endpoint)

		// Try to use advanced rate limiting algorithms if cache is available
		// Otherwise fall back to in-memory implementation
		if mgr := manager.GetManager(r.Context()); mgr != nil {
			cache := mgr.GetCache(manager.L2Cache)
			if cache != nil {
				// Use advanced rate limiting
				allowed, result, err := p.applyRateLimit(r.Context(), clientIP, endpointPattern, limits)
				if err != nil {
					// On error, log and allow request (fail open)
					slog.Warn("rate limit check error, allowing request", "error", err, "ip", clientIP, "endpoint", endpoint)
				}

				if !allowed {
					// If throttle is enabled, try to queue the request
					if p.Throttle != nil && p.Throttle.Enabled {
						if p.throttleRequest(w, r, next, result) {
							return
						}
						// throttleRequest returned false, meaning it handled the 429 response
						return
					}

					// Rate limit exceeded
					origin := "unknown"
					if p.config != nil {
						origin = p.config.ID
					}

					// Determine which limit was exceeded
					window := "minute"
					limit := limits.RequestsPerMinute
					if limits.RequestsPerHour > 0 && result.ResetTime.After(time.Now().Add(time.Hour)) {
						window = "hour"
						limit = limits.RequestsPerHour
					}
					if limits.RequestsPerDay > 0 && result.ResetTime.After(time.Now().Add(24*time.Hour)) {
						window = "day"
						limit = limits.RequestsPerDay
					}

					// Add headers
					p.addRateLimitHeaders(w, limits, result, window)

					// Log security event
					logging.LogRateLimitViolation(r.Context(), fmt.Sprintf("per_%s", window), clientIP, "", limit, window)
					emitSecurityRateLimited(r.Context(), p.config, r, fmt.Sprintf("per_%s", window), limit, window)

					metric.RateLimitViolation(origin, fmt.Sprintf("per_%s", window), clientIP, endpoint)

					// Set Retry-After header before WriteHeader
					if p.Headers.IncludeRetryAfter && result.RetryAfter > 0 {
						w.Header().Set("Retry-After", strconv.FormatInt(int64(result.RetryAfter.Seconds()), 10))
					}
					// Set status code
					reqctx.RecordPolicyViolation(r.Context(), "rate_limit", fmt.Sprintf("rate limit exceeded: %d requests per %s for endpoint %s", limit, window, endpoint))
					w.WriteHeader(http.StatusTooManyRequests)
					fmt.Fprintf(w, "rate limit exceeded: %d requests per %s for endpoint %s", limit, window, endpoint)
					return
				}

				// Add headers for successful request
				if limits.RequestsPerMinute > 0 {
					p.addRateLimitHeaders(w, limits, result, "minute")
				}

				// All checks passed, continue to next handler
				next.ServeHTTP(w, r)
				return
			}
		}

		// Fallback to in-memory implementation
		rateLimited, rateLimitResult, rateLimitWindow := p.checkInMemoryRateLimit(clientIP, endpoint, endpointPattern, limits)
		if rateLimited {
			// If throttle is enabled, try to queue the request
			if p.Throttle != nil && p.Throttle.Enabled {
				if p.throttleRequest(w, r, next, rateLimitResult) {
					return
				}
				// throttleRequest returned false, meaning it handled the 429 response
				return
			}

			origin := "unknown"
			if p.config != nil {
				origin = p.config.ID
			}

			p.addRateLimitHeaders(w, limits, rateLimitResult, rateLimitWindow)

			logging.LogRateLimitViolation(r.Context(), fmt.Sprintf("per_%s", rateLimitWindow), clientIP, "", p.getLimitForWindow(limits, rateLimitWindow), rateLimitWindow)
			emitSecurityRateLimited(r.Context(), p.config, r, fmt.Sprintf("per_%s", rateLimitWindow), p.getLimitForWindow(limits, rateLimitWindow), rateLimitWindow)

			metric.RateLimitViolation(origin, fmt.Sprintf("per_%s", rateLimitWindow), clientIP, endpoint)
			reqctx.RecordPolicyViolation(r.Context(), "rate_limit", fmt.Sprintf("rate limit exceeded: %d requests per %s for endpoint %s", p.getLimitForWindow(limits, rateLimitWindow), rateLimitWindow, endpoint))
			http.Error(w, fmt.Sprintf("rate limit exceeded: %d requests per %s for endpoint %s", p.getLimitForWindow(limits, rateLimitWindow), rateLimitWindow, endpoint), http.StatusTooManyRequests)
			return
		}

		// Calculate result for successful request (for headers on allowed requests)
		p.mu.RLock()
		counterKey := p.getCounterKey(clientIP, endpointPattern)
		counters := p.counters[counterKey]
		var successResult ratelimit.Result
		var activeWindow string
		if counters != nil {
			if limits.RequestsPerMinute > 0 {
				successResult = ratelimit.Result{
					Allowed:   true,
					Remaining: limits.RequestsPerMinute - counters.minuteCount,
					ResetTime: counters.lastMinute.Add(time.Minute),
				}
				activeWindow = "minute"
			} else if limits.RequestsPerHour > 0 {
				successResult = ratelimit.Result{
					Allowed:   true,
					Remaining: limits.RequestsPerHour - counters.hourCount,
					ResetTime: counters.lastHour.Add(time.Hour),
				}
				activeWindow = "hour"
			} else if limits.RequestsPerDay > 0 {
				successResult = ratelimit.Result{
					Allowed:   true,
					Remaining: limits.RequestsPerDay - counters.dayCount,
					ResetTime: counters.lastDay.Add(24 * time.Hour),
				}
				activeWindow = "day"
			}
		}
		p.mu.RUnlock()

		// Add rate limit headers for successful requests
		if activeWindow != "" {
			p.addRateLimitHeaders(w, limits, successResult, activeWindow)
		}

		// All checks passed, continue to next handler
		next.ServeHTTP(w, r)
	})
}

// smoothedLimit applies rate limit smoothing by scaling down the limit for new consumers.
func (p *RateLimitingPolicyConfig) smoothedLimit(baseLimit int, counters *rateLimitCounters) int {
	if p.Smoothing == nil || baseLimit <= 0 || counters == nil {
		return baseLimit
	}

	rampDuration := p.Smoothing.RampDuration.Duration
	if rampDuration <= 0 {
		rampDuration = time.Hour
	}
	initialRate := p.Smoothing.InitialRate
	if initialRate <= 0 {
		initialRate = 0.1
	}
	if initialRate >= 1.0 {
		return baseLimit
	}

	elapsed := time.Since(counters.firstSeen)
	if elapsed >= rampDuration {
		return baseLimit
	}

	progress := float64(elapsed) / float64(rampDuration)
	rate := initialRate + (1.0-initialRate)*progress
	result := int(float64(baseLimit) * rate)
	if result < 1 {
		result = 1
	}
	return result
}

// checkInMemoryRateLimit checks rate limits using in-memory counters.
// Returns (rateLimited bool, result, window string).
func (p *RateLimitingPolicyConfig) checkInMemoryRateLimit(clientIP, endpoint, endpointPattern string, limits RateLimit) (bool, ratelimit.Result, string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	counterKey := p.getCounterKey(clientIP, endpointPattern)
	counters := p.getOrCreateCounters(counterKey)

	// Apply smoothing to limits for new consumers
	if p.Smoothing != nil {
		limits.RequestsPerMinute = p.smoothedLimit(limits.RequestsPerMinute, counters)
		limits.RequestsPerHour = p.smoothedLimit(limits.RequestsPerHour, counters)
		limits.RequestsPerDay = p.smoothedLimit(limits.RequestsPerDay, counters)
	}

	// Check minute limit
	if limits.RequestsPerMinute > 0 {
		if now.Sub(counters.lastMinute) > time.Minute {
			counters.minuteCount = 0
			counters.lastMinute = now
		}
		counters.minuteCount++
		if counters.minuteCount > limits.RequestsPerMinute {
			remaining := limits.RequestsPerMinute - counters.minuteCount
			resetTime := counters.lastMinute.Add(time.Minute)
			return true, ratelimit.Result{
				Allowed:    false,
				Remaining:  remaining,
				ResetTime:  resetTime,
				RetryAfter: time.Until(resetTime),
			}, "minute"
		}
	}

	// Check hour limit
	if limits.RequestsPerHour > 0 {
		if now.Sub(counters.lastHour) > time.Hour {
			counters.hourCount = 0
			counters.lastHour = now
		}
		counters.hourCount++
		if counters.hourCount > limits.RequestsPerHour {
			remaining := limits.RequestsPerHour - counters.hourCount
			resetTime := counters.lastHour.Add(time.Hour)
			return true, ratelimit.Result{
				Allowed:    false,
				Remaining:  remaining,
				ResetTime:  resetTime,
				RetryAfter: time.Until(resetTime),
			}, "hour"
		}
	}

	// Check day limit
	if limits.RequestsPerDay > 0 {
		if now.Sub(counters.lastDay) > 24*time.Hour {
			counters.dayCount = 0
			counters.lastDay = now
		}
		counters.dayCount++
		if counters.dayCount > limits.RequestsPerDay {
			remaining := limits.RequestsPerDay - counters.dayCount
			resetTime := counters.lastDay.Add(24 * time.Hour)
			return true, ratelimit.Result{
				Allowed:    false,
				Remaining:  remaining,
				ResetTime:  resetTime,
				RetryAfter: time.Until(resetTime),
			}, "day"
		}
	}

	return false, ratelimit.Result{}, ""
}

// getLimitForWindow returns the limit value for the given window name.
func (p *RateLimitingPolicyConfig) getLimitForWindow(limits RateLimit, window string) int {
	switch window {
	case "minute":
		return limits.RequestsPerMinute
	case "hour":
		return limits.RequestsPerHour
	case "day":
		return limits.RequestsPerDay
	}
	return 0
}

// throttleRequest queues a rate-limited request and waits for a token.
// Returns true if the request was successfully served after waiting.
// Returns false if the request should be rejected (queue full or timeout).
func (p *RateLimitingPolicyConfig) throttleRequest(w http.ResponseWriter, r *http.Request, next http.Handler, result ratelimit.Result) bool {
	if p.throttleQueue == nil {
		return false
	}

	// Try to enqueue (non-blocking) - if queue is full, reject immediately
	select {
	case p.throttleQueue <- struct{}{}:
		// Successfully enqueued
	default:
		// Queue is full, return 429
		retryAfter := result.RetryAfter
		if retryAfter <= 0 {
			retryAfter = time.Second
		}
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
		reqctx.RecordPolicyViolation(r.Context(), "rate_limit", "rate limit exceeded: throttle queue full")
		http.Error(w, "rate limit exceeded: throttle queue full", http.StatusTooManyRequests)
		return false
	}

	// Determine max wait duration
	maxWait := p.Throttle.MaxWait.Duration
	if maxWait <= 0 {
		maxWait = 5 * time.Second
	}

	// Wait for the retry-after period or max wait, whichever is shorter
	waitDuration := result.RetryAfter
	if waitDuration <= 0 {
		waitDuration = time.Second
	}
	if waitDuration > maxWait {
		waitDuration = maxWait
	}

	timer := time.NewTimer(waitDuration)
	defer timer.Stop()

	select {
	case <-timer.C:
		// Dequeue
		<-p.throttleQueue
		// Serve the request after waiting
		next.ServeHTTP(w, r)
		return true
	case <-r.Context().Done():
		// Request was cancelled
		<-p.throttleQueue
		return false
	}
}

// checkQuota checks per-consumer quota limits and adds quota headers.
// Returns true if the request is within quota, false if quota is exceeded.
func (p *RateLimitingPolicyConfig) checkQuota(w http.ResponseWriter, r *http.Request, clientIP, endpoint string) bool {
	p.mu.Lock()
	now := time.Now().UTC()
	counterKey := "quota:" + clientIP
	counters := p.getOrCreateCounters(counterKey)

	renewal := p.Quota.Renewal
	if renewal == "" {
		renewal = "calendar"
	}

	// Check and reset daily quota
	if p.Quota.Daily > 0 {
		if counters.quotaDailyReset.IsZero() {
			counters.quotaDailyReset = p.nextDailyReset(now, renewal)
		}
		if now.After(counters.quotaDailyReset) {
			counters.quotaDailyCount = 0
			counters.quotaDailyReset = p.nextDailyReset(now, renewal)
		}
		counters.quotaDailyCount++
		if counters.quotaDailyCount > p.Quota.Daily {
			remaining := 0
			resetTime := counters.quotaDailyReset
			p.mu.Unlock()
			w.Header().Set("X-Quota-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-Quota-Reset", strconv.FormatInt(resetTime.Unix(), 10))
			reqctx.RecordPolicyViolation(r.Context(), "rate_limit", fmt.Sprintf("daily quota exceeded: %d requests per day", p.Quota.Daily))
			http.Error(w, fmt.Sprintf("daily quota exceeded: %d requests per day", p.Quota.Daily), http.StatusTooManyRequests)
			return false
		}
	}

	// Check and reset monthly quota
	if p.Quota.Monthly > 0 {
		if counters.quotaMonthlyReset.IsZero() {
			counters.quotaMonthlyReset = p.nextMonthlyReset(now, renewal)
		}
		if now.After(counters.quotaMonthlyReset) {
			counters.quotaMonthlyCount = 0
			counters.quotaMonthlyReset = p.nextMonthlyReset(now, renewal)
		}
		counters.quotaMonthlyCount++
		if counters.quotaMonthlyCount > p.Quota.Monthly {
			remaining := 0
			resetTime := counters.quotaMonthlyReset
			p.mu.Unlock()
			w.Header().Set("X-Quota-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-Quota-Reset", strconv.FormatInt(resetTime.Unix(), 10))
			reqctx.RecordPolicyViolation(r.Context(), "rate_limit", fmt.Sprintf("monthly quota exceeded: %d requests per month", p.Quota.Monthly))
			http.Error(w, fmt.Sprintf("monthly quota exceeded: %d requests per month", p.Quota.Monthly), http.StatusTooManyRequests)
			return false
		}
	}

	// Add quota remaining headers for successful requests
	if p.Quota.Daily > 0 {
		remaining := p.Quota.Daily - counters.quotaDailyCount
		if remaining < 0 {
			remaining = 0
		}
		w.Header().Set("X-Quota-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-Quota-Reset", strconv.FormatInt(counters.quotaDailyReset.Unix(), 10))
	} else if p.Quota.Monthly > 0 {
		remaining := p.Quota.Monthly - counters.quotaMonthlyCount
		if remaining < 0 {
			remaining = 0
		}
		w.Header().Set("X-Quota-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-Quota-Reset", strconv.FormatInt(counters.quotaMonthlyReset.Unix(), 10))
	}

	p.mu.Unlock()
	return true
}

// nextDailyReset calculates the next daily reset time.
func (p *RateLimitingPolicyConfig) nextDailyReset(now time.Time, renewal string) time.Time {
	if renewal == "rolling" {
		return now.Add(24 * time.Hour)
	}
	// Calendar: next midnight UTC
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	return next
}

// nextMonthlyReset calculates the next monthly reset time.
func (p *RateLimitingPolicyConfig) nextMonthlyReset(now time.Time, renewal string) time.Time {
	if renewal == "rolling" {
		return now.Add(30 * 24 * time.Hour)
	}
	// Calendar: 1st of next month UTC
	if now.Month() == 12 {
		return time.Date(now.Year()+1, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
}

// ApplyMessage performs the apply message operation on the RateLimitingPolicyConfig.
func (p *RateLimitingPolicyConfig) ApplyMessage(next MessageHandler) MessageHandler {
	return func(ctx context.Context, msg *MessageContext) error {
		if p.Disabled || p.Match == nil || !p.Match.MatchesMessage(msg) {
			return next(ctx, msg)
		}

		limits := RateLimit{
			Algorithm:         p.Algorithm,
			RequestsPerMinute: p.RequestsPerMinute,
			RequestsPerHour:   p.RequestsPerHour,
			RequestsPerDay:    p.RequestsPerDay,
			BurstSize:         p.BurstSize,
			RefillRate:        p.RefillRate,
			QueueSize:         p.QueueSize,
			DrainRate:         p.DrainRate,
		}

		key := p.messageCounterKey(msg)
		if key == "" {
			return next(ctx, msg)
		}

		allowed := p.allowWebSocketMessage(key, limits)
		if !allowed {
			if msg.Request != nil {
				logging.LogRateLimitViolation(ctx, "websocket_message", requestEventIP(msg.Request), "", limits.RequestsPerMinute, "message")
				emitSecurityRateLimited(ctx, p.config, msg.Request, "websocket_message", maxInt(limits.RequestsPerMinute, maxInt(limits.RequestsPerHour, limits.RequestsPerDay)), "message")
			}
			return newWebSocketCloseError(websocket.ClosePolicyViolation, "websocket rate limit exceeded", nil)
		}

		return next(ctx, msg)
	}
}

func (p *RateLimitingPolicyConfig) messageCounterKey(msg *MessageContext) string {
	if msg == nil {
		return ""
	}

	if msg.Request != nil {
		if rd := reqctx.GetRequestData(msg.Request.Context()); rd != nil && rd.SessionData != nil && rd.SessionData.AuthData != nil {
			for _, key := range []string{"sub", "subject", "user_id", "id"} {
				if value, ok := rd.SessionData.AuthData.Data[key].(string); ok && value != "" {
					return "subject:" + value
				}
			}
		}
	}

	if msg.Request != nil {
		if ip := requestEventIP(msg.Request); ip != "" {
			return "ip:" + ip
		}
	}

	if msg.ConnectionID != "" {
		return "connection:" + msg.ConnectionID
	}

	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (p *RateLimitingPolicyConfig) allowWebSocketMessage(counterKey string, limits RateLimit) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	counters := p.getOrCreateCounters(counterKey)

	if limits.RequestsPerMinute > 0 {
		if now.Sub(counters.lastMinute) >= time.Minute {
			counters.minuteCount = 0
			counters.lastMinute = now
		}
		counters.minuteCount++
		if counters.minuteCount > limits.RequestsPerMinute {
			return false
		}
	}

	if limits.RequestsPerHour > 0 {
		if now.Sub(counters.lastHour) >= time.Hour {
			counters.hourCount = 0
			counters.lastHour = now
		}
		counters.hourCount++
		if counters.hourCount > limits.RequestsPerHour {
			return false
		}
	}

	if limits.RequestsPerDay > 0 {
		if now.Sub(counters.lastDay) >= 24*time.Hour {
			counters.dayCount = 0
			counters.lastDay = now
		}
		counters.dayCount++
		if counters.dayCount > limits.RequestsPerDay {
			return false
		}
	}

	return true
}

// getLimitsForRequest returns the effective rate limits for a request
// It checks both IP-based custom limits and endpoint-based limits, returning the more restrictive
// Returns: (effective limits, endpoint pattern used for counter key)
func (p *RateLimitingPolicyConfig) getLimitsForRequest(clientIP string, endpoint string) (RateLimit, string) {
	var ipLimits RateLimit
	var endpointLimits RateLimit
	var endpointPattern string

	// Get IP-based limits
	if p.CustomLimits != nil {
		if custom, exists := p.CustomLimits[clientIP]; exists {
			ipLimits = custom
		} else {
			ipLimits = RateLimit{
				RequestsPerMinute: p.RequestsPerMinute,
				RequestsPerHour:   p.RequestsPerHour,
				RequestsPerDay:    p.RequestsPerDay,
			}
		}
	} else {
		ipLimits = RateLimit{
			RequestsPerMinute: p.RequestsPerMinute,
			RequestsPerHour:   p.RequestsPerHour,
			RequestsPerDay:    p.RequestsPerDay,
		}
	}

	// Check endpoint-based limits
	if p.EndpointLimits != nil {
		// Try exact match first
		if endpointLimit, exists := p.EndpointLimits[endpoint]; exists {
			endpointLimits = endpointLimit
			endpointPattern = endpoint
		} else {
			// Try prefix match (longest matching prefix wins)
			longestMatch := ""
			for pattern, limit := range p.EndpointLimits {
				if strings.HasPrefix(endpoint, pattern) {
					if len(pattern) > len(longestMatch) {
						longestMatch = pattern
						endpointLimits = limit
					}
				}
			}
			if longestMatch != "" {
				endpointPattern = longestMatch
			}
		}
	}

	// If no endpoint-specific limits found, use IP limits and track by endpoint
	if endpointPattern == "" {
		endpointPattern = endpoint
		return ipLimits, endpointPattern
	}

	// Merge limits: use the more restrictive (lower) value for each time window
	effectiveLimits := RateLimit{
		Algorithm:         endpointLimits.Algorithm, // Prefer endpoint algorithm if set
		RequestsPerMinute: p.minNonZero(ipLimits.RequestsPerMinute, endpointLimits.RequestsPerMinute),
		RequestsPerHour:   p.minNonZero(ipLimits.RequestsPerHour, endpointLimits.RequestsPerHour),
		RequestsPerDay:    p.minNonZero(ipLimits.RequestsPerDay, endpointLimits.RequestsPerDay),
		BurstSize:         endpointLimits.BurstSize,  // Prefer endpoint burst size
		RefillRate:        endpointLimits.RefillRate, // Prefer endpoint refill rate
		QueueSize:         endpointLimits.QueueSize,  // Prefer endpoint queue size
		DrainRate:         endpointLimits.DrainRate,  // Prefer endpoint drain rate
	}

	// If endpoint doesn't specify algorithm, use IP or default
	if effectiveLimits.Algorithm == "" {
		effectiveLimits.Algorithm = ipLimits.Algorithm
		if effectiveLimits.Algorithm == "" {
			effectiveLimits.Algorithm = p.Algorithm
		}
	}

	// Merge burst/queue settings if not set in endpoint
	if effectiveLimits.BurstSize == 0 {
		effectiveLimits.BurstSize = ipLimits.BurstSize
		if effectiveLimits.BurstSize == 0 {
			effectiveLimits.BurstSize = p.BurstSize
		}
	}
	if effectiveLimits.RefillRate == 0 {
		effectiveLimits.RefillRate = ipLimits.RefillRate
		if effectiveLimits.RefillRate == 0 {
			effectiveLimits.RefillRate = p.RefillRate
		}
	}
	if effectiveLimits.QueueSize == 0 {
		effectiveLimits.QueueSize = ipLimits.QueueSize
		if effectiveLimits.QueueSize == 0 {
			effectiveLimits.QueueSize = p.QueueSize
		}
	}
	if effectiveLimits.DrainRate == 0 {
		effectiveLimits.DrainRate = ipLimits.DrainRate
		if effectiveLimits.DrainRate == 0 {
			effectiveLimits.DrainRate = p.DrainRate
		}
	}

	return effectiveLimits, endpointPattern
}

// minNonZero returns the minimum of two values, ignoring zero values
// If one value is zero, returns the other. If both are zero, returns 0.
func (p *RateLimitingPolicyConfig) minNonZero(a, b int) int {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// getCounterKey generates a unique key for rate limit counters
// Format: "IP:endpoint" for per-endpoint limits, or "IP" for IP-only limits
func (p *RateLimitingPolicyConfig) getCounterKey(clientIP string, endpointPattern string) string {
	// If endpoint limits are configured, use IP:endpoint as key
	if len(p.EndpointLimits) > 0 {
		return fmt.Sprintf("%s:%s", clientIP, endpointPattern)
	}
	// Otherwise, use IP only (backward compatible)
	return clientIP
}

func (p *RateLimitingPolicyConfig) getOrCreateCounters(counterKey string) *rateLimitCounters {
	if counters, exists := p.counters[counterKey]; exists {
		counters.lastAccess = time.Now()
		return counters
	}

	// Enforce max size before adding a new entry.
	// If at capacity, evict the entry with the oldest lastAccess.
	if len(p.counters) >= maxRateLimitCounters {
		p.evictOldestCounter()
	}

	now := time.Now()
	counters := &rateLimitCounters{
		firstSeen:  now,
		lastMinute: now,
		lastHour:   now,
		lastDay:    now,
		lastAccess: now,
	}
	p.counters[counterKey] = counters
	return counters
}

// evictOldestCounter removes the counter entry with the oldest lastAccess timestamp.
// Must be called with p.mu held.
func (p *RateLimitingPolicyConfig) evictOldestCounter() {
	var oldestKey string
	var oldestTime time.Time

	for key, counters := range p.counters {
		if oldestKey == "" || counters.lastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = counters.lastAccess
		}
	}

	if oldestKey != "" {
		delete(p.counters, oldestKey)
	}
}

// addRateLimitHeaders adds rate limit headers to the response following
// IETF draft-polli-ratelimit-headers-02 specification with X- prefix
// https://www.ietf.org/archive/id/draft-polli-ratelimit-headers-02.html
func (p *RateLimitingPolicyConfig) addRateLimitHeaders(w http.ResponseWriter, limits RateLimit, result ratelimit.Result, window string) {
	if !p.Headers.Enabled {
		return
	}

	limit := 0
	switch window {
	case "minute":
		limit = limits.RequestsPerMinute
	case "hour":
		limit = limits.RequestsPerHour
	case "day":
		limit = limits.RequestsPerDay
	}

	if limit <= 0 {
		return
	}

	// Determine header prefix (default: "X-RateLimit")
	prefix := p.Headers.HeaderPrefix
	if prefix == "" {
		prefix = "X-RateLimit"
	}

	// Check if any specific headers are enabled, if none specified, include all by default
	includeAll := !p.Headers.IncludeLimit && !p.Headers.IncludeRemaining &&
		!p.Headers.IncludeReset && !p.Headers.IncludeUsed

	// X-RateLimit-Limit: the requests quota in the time window
	if includeAll || p.Headers.IncludeLimit {
		w.Header().Set(prefix+"-Limit", strconv.Itoa(limit))
	}

	// X-RateLimit-Remaining: remaining requests quota in the current window
	if includeAll || p.Headers.IncludeRemaining {
		remaining := result.Remaining
		if remaining < 0 {
			remaining = 0
		}
		w.Header().Set(prefix+"-Remaining", strconv.Itoa(remaining))
	}

	// X-RateLimit-Reset: time until window resets
	// Per IETF spec, this should be in delta-seconds (seconds remaining)
	if includeAll || p.Headers.IncludeReset {
		resetFormat := p.Headers.ResetFormat
		if resetFormat == "" {
			resetFormat = "delta_seconds" // IETF spec default
		}

		if resetFormat == "unix_timestamp" {
			// Unix timestamp when the window resets
			w.Header().Set(prefix+"-Reset", strconv.FormatInt(result.ResetTime.Unix(), 10))
		} else {
			// delta_seconds: seconds remaining until reset (IETF spec compliant)
			deltaSeconds := int64(time.Until(result.ResetTime).Seconds())
			if deltaSeconds < 0 {
				deltaSeconds = 0
			}
			w.Header().Set(prefix+"-Reset", strconv.FormatInt(deltaSeconds, 10))
		}
	}

	// X-RateLimit-Used: requests used in current window (non-standard but useful)
	if includeAll || p.Headers.IncludeUsed {
		used := limit - result.Remaining
		if used < 0 {
			used = 0
		}
		w.Header().Set(prefix+"-Used", strconv.Itoa(used))
	}

	// Retry-After header (standard HTTP header, always without prefix)
	if p.Headers.IncludeRetryAfter && result.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(result.RetryAfter.Seconds()), 10))
	}
}

// applyRateLimit checks rate limits using the configured algorithm
func (p *RateLimitingPolicyConfig) applyRateLimit(ctx context.Context, clientIP string, endpoint string, limits RateLimit) (bool, ratelimit.Result, error) {
	// Try to get cache from manager (for distributed rate limiting)
	var cache cacher.Cacher
	if mgr := manager.GetManager(ctx); mgr != nil {
		cache = mgr.GetCache(manager.L2Cache)
	}

	// Determine algorithm
	algorithm := limits.Algorithm
	if algorithm == "" {
		algorithm = p.Algorithm
	}
	if algorithm == "" {
		algorithm = "sliding_window" // Default
	}

	// Convert algorithm string to type
	algType := ratelimit.AlgorithmType(algorithm)
	if algType != ratelimit.AlgorithmSlidingWindow &&
		algType != ratelimit.AlgorithmTokenBucket &&
		algType != ratelimit.AlgorithmLeakyBucket &&
		algType != ratelimit.AlgorithmFixedWindow {
		algType = ratelimit.AlgorithmSlidingWindow // Fallback to default
	}

	// Create rate limiter
	config := ratelimit.Config{
		Algorithm:  algType,
		BurstSize:  limits.BurstSize,
		RefillRate: limits.RefillRate,
		QueueSize:  limits.QueueSize,
		DrainRate:  limits.DrainRate,
		Cache:      cache,
		Prefix:     fmt.Sprintf("rl:%s", p.config.ID),
	}

	limiter := ratelimit.NewRateLimiter(cache, algType, config.Prefix, config)

	// Check each time window (minute, hour, day)
	var result ratelimit.Result
	var allowed bool = true
	var err error

	// Check minute limit
	if limits.RequestsPerMinute > 0 {
		key := fmt.Sprintf("%s:%s:minute", clientIP, endpoint)
		result, err = limiter.Allow(ctx, key, limits.RequestsPerMinute, time.Minute)
		if err != nil {
			// On error, allow request (fail open)
			return true, result, err
		}
		if !result.Allowed {
			return false, result, nil
		}
	}

	// Check hour limit
	if limits.RequestsPerHour > 0 {
		key := fmt.Sprintf("%s:%s:hour", clientIP, endpoint)
		result, err = limiter.Allow(ctx, key, limits.RequestsPerHour, time.Hour)
		if err != nil {
			return true, result, err
		}
		if !result.Allowed {
			return false, result, nil
		}
	}

	// Check day limit
	if limits.RequestsPerDay > 0 {
		key := fmt.Sprintf("%s:%s:day", clientIP, endpoint)
		result, err = limiter.Allow(ctx, key, limits.RequestsPerDay, 24*time.Hour)
		if err != nil {
			return true, result, err
		}
		if !result.Allowed {
			return false, result, nil
		}
	}

	return allowed, result, nil
}

func (p *RateLimitingPolicyConfig) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			for key, counters := range p.counters {
				// Remove counters that haven't been accessed in the last hour
				if now.Sub(counters.lastAccess) > time.Hour {
					delete(p.counters, key)
				}
			}
			// After expiring stale entries, enforce max size by evicting oldest
			for len(p.counters) > maxRateLimitCounters {
				p.evictOldestCounter()
			}
			p.mu.Unlock()
		}
	}
}

// parseIPList parses a list of IP addresses or CIDR ranges
func parseIPList(list []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(list))
	for _, cidr := range list {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			result = append(result, ipNet)
		} else if ip := net.ParseIP(cidr); ip != nil {
			_, ipNet, _ := net.ParseCIDR(cidr + "/32")
			result = append(result, ipNet)
		}
	}
	return result
}
