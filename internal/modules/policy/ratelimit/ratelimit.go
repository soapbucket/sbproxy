// Package ratelimit registers the rate_limiting policy.
//
// Rate Limiting: In-Memory vs. Distributed
//
// The in-memory rate limiter (counters map) is per-process only. Each proxy instance
// maintains its own independent counters, so a client can exceed the configured limit
// by a factor of N where N is the number of proxy instances. For accurate rate limiting
// across multiple instances, configure a Redis-backed cache (L2 cache) so the advanced
// rate limiting path is used instead. The in-memory fallback is suitable for single-instance
// deployments or as a best-effort safety net when Redis is unavailable.
package ratelimit

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

	cacher "github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/request/ratelimit"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("rate_limiting", New)
}

// Duration wraps time.Duration for JSON unmarshaling from string.
type Duration struct {
	Duration time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// RateLimit holds per-consumer rate limit configuration.
type RateLimit struct {
	Algorithm         string  `json:"algorithm,omitempty"`
	RequestsPerMinute int     `json:"requests_per_minute,omitempty"`
	RequestsPerHour   int     `json:"requests_per_hour,omitempty"`
	RequestsPerDay    int     `json:"requests_per_day,omitempty"`
	BurstSize         int     `json:"burst_size,omitempty"`
	RefillRate        float64 `json:"refill_rate,omitempty"`
	QueueSize         int     `json:"queue_size,omitempty"`
	DrainRate         float64 `json:"drain_rate,omitempty"`
}

// ThrottleConfig configures request queuing behavior.
type ThrottleConfig struct {
	Enabled  bool     `json:"enabled,omitempty"`
	MaxQueue int      `json:"max_queue,omitempty"`
	MaxWait  Duration `json:"max_wait,omitempty"`
}

// QuotaConfig configures per-consumer quota tracking.
type QuotaConfig struct {
	Daily   int    `json:"daily,omitempty"`
	Monthly int    `json:"monthly,omitempty"`
	Renewal string `json:"renewal,omitempty"`
}

// SmoothingConfig configures gradual rate limit ramp-up.
type SmoothingConfig struct {
	RampDuration Duration `json:"ramp_duration,omitempty"`
	InitialRate  float64  `json:"initial_rate,omitempty"`
}

// RateLimitHeadersConfig holds rate limit header configuration.
type RateLimitHeadersConfig struct {
	Enabled           bool   `json:"enabled,omitempty"`
	IncludeRetryAfter bool   `json:"include_retry_after,omitempty"`
	IncludeLimit      bool   `json:"include_limit,omitempty"`
	IncludeRemaining  bool   `json:"include_remaining,omitempty"`
	IncludeReset      bool   `json:"include_reset,omitempty"`
	IncludeUsed       bool   `json:"include_used,omitempty"`
	ResetFormat       string `json:"reset_format,omitempty"`
	HeaderPrefix      string `json:"header_prefix,omitempty"`
}

// Config holds configuration for the rate_limiting policy.
type Config struct {
	Type              string                 `json:"type"`
	Disabled          bool                   `json:"disabled,omitempty"`
	Algorithm         string                 `json:"algorithm,omitempty"`
	RequestsPerMinute int                    `json:"requests_per_minute,omitempty"`
	RequestsPerHour   int                    `json:"requests_per_hour,omitempty"`
	RequestsPerDay    int                    `json:"requests_per_day,omitempty"`
	BurstSize         int                    `json:"burst_size,omitempty"`
	RefillRate        float64                `json:"refill_rate,omitempty"`
	QueueSize         int                    `json:"queue_size,omitempty"`
	DrainRate         float64                `json:"drain_rate,omitempty"`
	Whitelist         []string               `json:"whitelist,omitempty"`
	Blacklist         []string               `json:"blacklist,omitempty"`
	CustomLimits      map[string]RateLimit   `json:"custom_limits,omitempty"`
	EndpointLimits    map[string]RateLimit   `json:"endpoint_limits,omitempty"`
	Headers           RateLimitHeadersConfig `json:"headers,omitempty"`
	Throttle          *ThrottleConfig        `json:"throttle,omitempty"`
	Quota             *QuotaConfig           `json:"quota,omitempty"`
	Smoothing         *SmoothingConfig       `json:"smoothing,omitempty"`
}

const maxRateLimitCounters = 100000

type rateLimitCounters struct {
	firstSeen         time.Time
	minuteCount       int
	hourCount         int
	dayCount          int
	lastMinute        time.Time
	lastHour          time.Time
	lastDay           time.Time
	lastAccess        time.Time
	quotaDailyCount   int
	quotaMonthlyCount int
	quotaDailyReset   time.Time
	quotaMonthlyReset time.Time
}

// New creates a new rate_limiting policy enforcer.
func New(data json.RawMessage) (plugin.PolicyEnforcer, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	p := &rateLimitPolicy{
		cfg:       cfg,
		counters:  make(map[string]*rateLimitCounters),
		whitelist: parseIPList(cfg.Whitelist),
		blacklist: parseIPList(cfg.Blacklist),
	}

	return p, nil
}

type rateLimitPolicy struct {
	cfg           *Config
	whitelist     []*net.IPNet
	blacklist     []*net.IPNet
	mu            sync.RWMutex
	counters      map[string]*rateLimitCounters
	throttleQueue chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
	// Fields populated from PluginContext.
	originID    string
	workspaceID string
	hostname    string
}

func (p *rateLimitPolicy) Type() string { return "rate_limiting" }

// InitPlugin implements plugin.Initable.
func (p *rateLimitPolicy) InitPlugin(ctx plugin.PluginContext) error {
	p.originID = ctx.OriginID
	p.workspaceID = ctx.WorkspaceID
	p.hostname = ctx.Hostname

	p.ctx, p.cancel = context.WithCancel(context.Background())
	go p.cleanup()

	if p.cfg.Throttle != nil && p.cfg.Throttle.Enabled {
		maxQueue := p.cfg.Throttle.MaxQueue
		if maxQueue <= 0 {
			maxQueue = 100
		}
		p.throttleQueue = make(chan struct{}, maxQueue)
	}

	slog.Warn("rate limiter initialized in per-instance in-memory mode; configure Redis (L2 cache) for accurate multi-instance rate limiting",
		"config_id", p.originID)

	return nil
}

func (p *rateLimitPolicy) Enforce(next http.Handler) http.Handler {
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

		parsedIP := net.ParseIP(clientIP)
		if parsedIP == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Check whitelist.
		for _, ipNet := range p.whitelist {
			if ipNet.Contains(parsedIP) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check blacklist.
		for _, ipNet := range p.blacklist {
			if ipNet.Contains(parsedIP) {
				reqctx.RecordPolicyViolation(r.Context(), "rate_limit", "IP address is blacklisted")
				http.Error(w, "IP address is blacklisted", http.StatusTooManyRequests)
				return
			}
		}

		endpoint := r.URL.Path
		if endpoint == "" {
			endpoint = "/"
		}

		// Check quota.
		if p.cfg.Quota != nil && (p.cfg.Quota.Daily > 0 || p.cfg.Quota.Monthly > 0) {
			if !p.checkQuota(w, r, clientIP, endpoint) {
				return
			}
		}

		limits, endpointPattern := p.getLimitsForRequest(clientIP, endpoint)

		// Try advanced rate limiting with cache.
		if mgr := manager.GetManager(r.Context()); mgr != nil {
			cache := mgr.GetCache(manager.L2Cache)
			if cache != nil {
				allowed, result, err := p.applyRateLimit(r.Context(), clientIP, endpointPattern, limits)
				if err != nil {
					slog.Warn("rate limit check error, allowing request", "error", err, "ip", clientIP, "endpoint", endpoint)
				}

				if !allowed {
					if p.cfg.Throttle != nil && p.cfg.Throttle.Enabled {
						if p.throttleRequest(w, r, next, result) {
							return
						}
						return
					}

					origin := p.originID
					if origin == "" {
						origin = "unknown"
					}

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

					p.addRateLimitHeaders(w, limits, result, window)
					logging.LogRateLimitViolation(r.Context(), fmt.Sprintf("per_%s", window), clientIP, "", limit, window)
					p.emitRateLimited(r.Context(), r, fmt.Sprintf("per_%s", window), limit, window)
					metric.RateLimitViolation(origin, fmt.Sprintf("per_%s", window), clientIP, endpoint)

					if p.cfg.Headers.IncludeRetryAfter && result.RetryAfter > 0 {
						w.Header().Set("Retry-After", strconv.FormatInt(int64(result.RetryAfter.Seconds()), 10))
					}
					reqctx.RecordPolicyViolation(r.Context(), "rate_limit", fmt.Sprintf("rate limit exceeded: %d requests per %s for endpoint %s", limit, window, endpoint))
					w.WriteHeader(http.StatusTooManyRequests)
					fmt.Fprintf(w, "rate limit exceeded: %d requests per %s for endpoint %s", limit, window, endpoint)
					return
				}

				if limits.RequestsPerMinute > 0 {
					p.addRateLimitHeaders(w, limits, result, "minute")
				}
				next.ServeHTTP(w, r)
				return
			}
		}

		// Fallback: in-memory rate limiting.
		rateLimited, rateLimitResult, rateLimitWindow := p.checkInMemoryRateLimit(clientIP, endpoint, endpointPattern, limits)
		if rateLimited {
			if p.cfg.Throttle != nil && p.cfg.Throttle.Enabled {
				if p.throttleRequest(w, r, next, rateLimitResult) {
					return
				}
				return
			}

			origin := p.originID
			if origin == "" {
				origin = "unknown"
			}

			p.addRateLimitHeaders(w, limits, rateLimitResult, rateLimitWindow)
			logging.LogRateLimitViolation(r.Context(), fmt.Sprintf("per_%s", rateLimitWindow), clientIP, "", p.getLimitForWindow(limits, rateLimitWindow), rateLimitWindow)
			p.emitRateLimited(r.Context(), r, fmt.Sprintf("per_%s", rateLimitWindow), p.getLimitForWindow(limits, rateLimitWindow), rateLimitWindow)
			metric.RateLimitViolation(origin, fmt.Sprintf("per_%s", rateLimitWindow), clientIP, endpoint)
			reqctx.RecordPolicyViolation(r.Context(), "rate_limit", fmt.Sprintf("rate limit exceeded: %d requests per %s for endpoint %s", p.getLimitForWindow(limits, rateLimitWindow), rateLimitWindow, endpoint))
			http.Error(w, fmt.Sprintf("rate limit exceeded: %d requests per %s for endpoint %s", p.getLimitForWindow(limits, rateLimitWindow), rateLimitWindow, endpoint), http.StatusTooManyRequests)
			return
		}

		// Build headers for successful request.
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

		if activeWindow != "" {
			p.addRateLimitHeaders(w, limits, successResult, activeWindow)
		}

		next.ServeHTTP(w, r)
	})
}

func (p *rateLimitPolicy) emitRateLimited(ctx context.Context, r *http.Request, policyName string, limit int, window string) {
	if p.workspaceID == "" {
		return
	}
	event := &events.SecurityRateLimited{
		EventBase:  events.NewBase("security.rate_limited", events.SeverityWarning, p.workspaceID, reqctx.GetRequestID(ctx)),
		IP:         requestEventIP(r),
		Path:       requestPath(r),
		PolicyName: policyName,
		Limit:      limit,
		Window:     window,
	}
	event.Origin = events.OriginContext{
		OriginID:    p.originID,
		Hostname:    p.hostname,
		WorkspaceID: p.workspaceID,
	}
	events.Emit(ctx, p.workspaceID, event)
}

func (p *rateLimitPolicy) smoothedLimit(baseLimit int, counters *rateLimitCounters) int {
	if p.cfg.Smoothing == nil || baseLimit <= 0 || counters == nil {
		return baseLimit
	}
	rampDuration := p.cfg.Smoothing.RampDuration.Duration
	if rampDuration <= 0 {
		rampDuration = time.Hour
	}
	initialRate := p.cfg.Smoothing.InitialRate
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

func (p *rateLimitPolicy) checkInMemoryRateLimit(clientIP, endpoint, endpointPattern string, limits RateLimit) (bool, ratelimit.Result, string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	counterKey := p.getCounterKey(clientIP, endpointPattern)
	counters := p.getOrCreateCounters(counterKey)

	if p.cfg.Smoothing != nil {
		limits.RequestsPerMinute = p.smoothedLimit(limits.RequestsPerMinute, counters)
		limits.RequestsPerHour = p.smoothedLimit(limits.RequestsPerHour, counters)
		limits.RequestsPerDay = p.smoothedLimit(limits.RequestsPerDay, counters)
	}

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

func (p *rateLimitPolicy) getLimitForWindow(limits RateLimit, window string) int {
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

func (p *rateLimitPolicy) throttleRequest(w http.ResponseWriter, r *http.Request, next http.Handler, result ratelimit.Result) bool {
	if p.throttleQueue == nil {
		return false
	}
	select {
	case p.throttleQueue <- struct{}{}:
	default:
		retryAfter := result.RetryAfter
		if retryAfter <= 0 {
			retryAfter = time.Second
		}
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
		reqctx.RecordPolicyViolation(r.Context(), "rate_limit", "rate limit exceeded: throttle queue full")
		http.Error(w, "rate limit exceeded: throttle queue full", http.StatusTooManyRequests)
		return false
	}

	maxWait := p.cfg.Throttle.MaxWait.Duration
	if maxWait <= 0 {
		maxWait = 5 * time.Second
	}
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
		<-p.throttleQueue
		next.ServeHTTP(w, r)
		return true
	case <-r.Context().Done():
		<-p.throttleQueue
		return false
	}
}

func (p *rateLimitPolicy) checkQuota(w http.ResponseWriter, r *http.Request, clientIP, endpoint string) bool {
	p.mu.Lock()
	now := time.Now().UTC()
	counterKey := "quota:" + clientIP
	counters := p.getOrCreateCounters(counterKey)

	renewal := p.cfg.Quota.Renewal
	if renewal == "" {
		renewal = "calendar"
	}

	if p.cfg.Quota.Daily > 0 {
		if counters.quotaDailyReset.IsZero() {
			counters.quotaDailyReset = p.nextDailyReset(now, renewal)
		}
		if now.After(counters.quotaDailyReset) {
			counters.quotaDailyCount = 0
			counters.quotaDailyReset = p.nextDailyReset(now, renewal)
		}
		counters.quotaDailyCount++
		if counters.quotaDailyCount > p.cfg.Quota.Daily {
			remaining := 0
			resetTime := counters.quotaDailyReset
			p.mu.Unlock()
			w.Header().Set("X-Quota-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-Quota-Reset", strconv.FormatInt(resetTime.Unix(), 10))
			reqctx.RecordPolicyViolation(r.Context(), "rate_limit", fmt.Sprintf("daily quota exceeded: %d requests per day", p.cfg.Quota.Daily))
			http.Error(w, fmt.Sprintf("daily quota exceeded: %d requests per day", p.cfg.Quota.Daily), http.StatusTooManyRequests)
			return false
		}
	}

	if p.cfg.Quota.Monthly > 0 {
		if counters.quotaMonthlyReset.IsZero() {
			counters.quotaMonthlyReset = p.nextMonthlyReset(now, renewal)
		}
		if now.After(counters.quotaMonthlyReset) {
			counters.quotaMonthlyCount = 0
			counters.quotaMonthlyReset = p.nextMonthlyReset(now, renewal)
		}
		counters.quotaMonthlyCount++
		if counters.quotaMonthlyCount > p.cfg.Quota.Monthly {
			remaining := 0
			resetTime := counters.quotaMonthlyReset
			p.mu.Unlock()
			w.Header().Set("X-Quota-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-Quota-Reset", strconv.FormatInt(resetTime.Unix(), 10))
			reqctx.RecordPolicyViolation(r.Context(), "rate_limit", fmt.Sprintf("monthly quota exceeded: %d requests per month", p.cfg.Quota.Monthly))
			http.Error(w, fmt.Sprintf("monthly quota exceeded: %d requests per month", p.cfg.Quota.Monthly), http.StatusTooManyRequests)
			return false
		}
	}

	if p.cfg.Quota.Daily > 0 {
		remaining := p.cfg.Quota.Daily - counters.quotaDailyCount
		if remaining < 0 {
			remaining = 0
		}
		w.Header().Set("X-Quota-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-Quota-Reset", strconv.FormatInt(counters.quotaDailyReset.Unix(), 10))
	} else if p.cfg.Quota.Monthly > 0 {
		remaining := p.cfg.Quota.Monthly - counters.quotaMonthlyCount
		if remaining < 0 {
			remaining = 0
		}
		w.Header().Set("X-Quota-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-Quota-Reset", strconv.FormatInt(counters.quotaMonthlyReset.Unix(), 10))
	}

	p.mu.Unlock()
	return true
}

func (p *rateLimitPolicy) nextDailyReset(now time.Time, renewal string) time.Time {
	if renewal == "rolling" {
		return now.Add(24 * time.Hour)
	}
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
}

func (p *rateLimitPolicy) nextMonthlyReset(now time.Time, renewal string) time.Time {
	if renewal == "rolling" {
		return now.Add(30 * 24 * time.Hour)
	}
	if now.Month() == 12 {
		return time.Date(now.Year()+1, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
}

func (p *rateLimitPolicy) getLimitsForRequest(clientIP string, endpoint string) (RateLimit, string) {
	var ipLimits RateLimit
	var endpointLimits RateLimit
	var endpointPattern string

	if p.cfg.CustomLimits != nil {
		if custom, exists := p.cfg.CustomLimits[clientIP]; exists {
			ipLimits = custom
		} else {
			ipLimits = RateLimit{
				RequestsPerMinute: p.cfg.RequestsPerMinute,
				RequestsPerHour:   p.cfg.RequestsPerHour,
				RequestsPerDay:    p.cfg.RequestsPerDay,
			}
		}
	} else {
		ipLimits = RateLimit{
			RequestsPerMinute: p.cfg.RequestsPerMinute,
			RequestsPerHour:   p.cfg.RequestsPerHour,
			RequestsPerDay:    p.cfg.RequestsPerDay,
		}
	}

	if p.cfg.EndpointLimits != nil {
		if endpointLimit, exists := p.cfg.EndpointLimits[endpoint]; exists {
			endpointLimits = endpointLimit
			endpointPattern = endpoint
		} else {
			longestMatch := ""
			for pattern, limit := range p.cfg.EndpointLimits {
				if strings.HasPrefix(endpoint, pattern) && len(pattern) > len(longestMatch) {
					longestMatch = pattern
					endpointLimits = limit
				}
			}
			if longestMatch != "" {
				endpointPattern = longestMatch
			}
		}
	}

	if endpointPattern == "" {
		endpointPattern = endpoint
		return ipLimits, endpointPattern
	}

	effectiveLimits := RateLimit{
		Algorithm:         endpointLimits.Algorithm,
		RequestsPerMinute: p.minNonZero(ipLimits.RequestsPerMinute, endpointLimits.RequestsPerMinute),
		RequestsPerHour:   p.minNonZero(ipLimits.RequestsPerHour, endpointLimits.RequestsPerHour),
		RequestsPerDay:    p.minNonZero(ipLimits.RequestsPerDay, endpointLimits.RequestsPerDay),
		BurstSize:         endpointLimits.BurstSize,
		RefillRate:        endpointLimits.RefillRate,
		QueueSize:         endpointLimits.QueueSize,
		DrainRate:         endpointLimits.DrainRate,
	}

	if effectiveLimits.Algorithm == "" {
		effectiveLimits.Algorithm = ipLimits.Algorithm
		if effectiveLimits.Algorithm == "" {
			effectiveLimits.Algorithm = p.cfg.Algorithm
		}
	}
	if effectiveLimits.BurstSize == 0 {
		effectiveLimits.BurstSize = ipLimits.BurstSize
		if effectiveLimits.BurstSize == 0 {
			effectiveLimits.BurstSize = p.cfg.BurstSize
		}
	}
	if effectiveLimits.RefillRate == 0 {
		effectiveLimits.RefillRate = ipLimits.RefillRate
		if effectiveLimits.RefillRate == 0 {
			effectiveLimits.RefillRate = p.cfg.RefillRate
		}
	}
	if effectiveLimits.QueueSize == 0 {
		effectiveLimits.QueueSize = ipLimits.QueueSize
		if effectiveLimits.QueueSize == 0 {
			effectiveLimits.QueueSize = p.cfg.QueueSize
		}
	}
	if effectiveLimits.DrainRate == 0 {
		effectiveLimits.DrainRate = ipLimits.DrainRate
		if effectiveLimits.DrainRate == 0 {
			effectiveLimits.DrainRate = p.cfg.DrainRate
		}
	}

	return effectiveLimits, endpointPattern
}

func (p *rateLimitPolicy) minNonZero(a, b int) int {
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

func (p *rateLimitPolicy) getCounterKey(clientIP string, endpointPattern string) string {
	if len(p.cfg.EndpointLimits) > 0 {
		return fmt.Sprintf("%s:%s", clientIP, endpointPattern)
	}
	return clientIP
}

func (p *rateLimitPolicy) getOrCreateCounters(counterKey string) *rateLimitCounters {
	if counters, exists := p.counters[counterKey]; exists {
		counters.lastAccess = time.Now()
		return counters
	}
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

func (p *rateLimitPolicy) evictOldestCounter() {
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

func (p *rateLimitPolicy) addRateLimitHeaders(w http.ResponseWriter, limits RateLimit, result ratelimit.Result, window string) {
	if !p.cfg.Headers.Enabled {
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

	prefix := p.cfg.Headers.HeaderPrefix
	if prefix == "" {
		prefix = "X-RateLimit"
	}

	includeAll := !p.cfg.Headers.IncludeLimit && !p.cfg.Headers.IncludeRemaining &&
		!p.cfg.Headers.IncludeReset && !p.cfg.Headers.IncludeUsed

	if includeAll || p.cfg.Headers.IncludeLimit {
		w.Header().Set(prefix+"-Limit", strconv.Itoa(limit))
	}
	if includeAll || p.cfg.Headers.IncludeRemaining {
		remaining := result.Remaining
		if remaining < 0 {
			remaining = 0
		}
		w.Header().Set(prefix+"-Remaining", strconv.Itoa(remaining))
	}
	if includeAll || p.cfg.Headers.IncludeReset {
		resetFormat := p.cfg.Headers.ResetFormat
		if resetFormat == "" {
			resetFormat = "delta_seconds"
		}
		if resetFormat == "unix_timestamp" {
			w.Header().Set(prefix+"-Reset", strconv.FormatInt(result.ResetTime.Unix(), 10))
		} else {
			deltaSeconds := int64(time.Until(result.ResetTime).Seconds())
			if deltaSeconds < 0 {
				deltaSeconds = 0
			}
			w.Header().Set(prefix+"-Reset", strconv.FormatInt(deltaSeconds, 10))
		}
	}
	if includeAll || p.cfg.Headers.IncludeUsed {
		used := limit - result.Remaining
		if used < 0 {
			used = 0
		}
		w.Header().Set(prefix+"-Used", strconv.Itoa(used))
	}
	if p.cfg.Headers.IncludeRetryAfter && result.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(result.RetryAfter.Seconds()), 10))
	}
}

func (p *rateLimitPolicy) applyRateLimit(ctx context.Context, clientIP string, endpoint string, limits RateLimit) (bool, ratelimit.Result, error) {
	var cache cacher.Cacher
	if mgr := manager.GetManager(ctx); mgr != nil {
		cache = mgr.GetCache(manager.L2Cache)
	}

	algorithm := limits.Algorithm
	if algorithm == "" {
		algorithm = p.cfg.Algorithm
	}
	if algorithm == "" {
		algorithm = "sliding_window"
	}

	algType := ratelimit.AlgorithmType(algorithm)
	if algType != ratelimit.AlgorithmSlidingWindow &&
		algType != ratelimit.AlgorithmTokenBucket &&
		algType != ratelimit.AlgorithmLeakyBucket &&
		algType != ratelimit.AlgorithmFixedWindow {
		algType = ratelimit.AlgorithmSlidingWindow
	}

	originID := p.originID
	if originID == "" {
		originID = "unknown"
	}

	config := ratelimit.Config{
		Algorithm:  algType,
		BurstSize:  limits.BurstSize,
		RefillRate: limits.RefillRate,
		QueueSize:  limits.QueueSize,
		DrainRate:  limits.DrainRate,
		Cache:      cache,
		Prefix:     fmt.Sprintf("rl:%s", originID),
	}

	limiter := ratelimit.NewRateLimiter(cache, algType, config.Prefix, config)

	var result ratelimit.Result
	var allowed bool = true
	var err error

	if limits.RequestsPerMinute > 0 {
		key := fmt.Sprintf("%s:%s:minute", clientIP, endpoint)
		result, err = limiter.Allow(ctx, key, limits.RequestsPerMinute, time.Minute)
		if err != nil {
			return true, result, err
		}
		if !result.Allowed {
			return false, result, nil
		}
	}

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

func (p *rateLimitPolicy) cleanup() {
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
				if now.Sub(counters.lastAccess) > time.Hour {
					delete(p.counters, key)
				}
			}
			for len(p.counters) > maxRateLimitCounters {
				p.evictOldestCounter()
			}
			p.mu.Unlock()
		}
	}
}

// parseIPList parses a list of IP addresses or CIDR ranges.
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

func getClientIPFromRequest(req *http.Request) string {
	if req.RemoteAddr != "" {
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			return host
		}
		return req.RemoteAddr
	}
	return ""
}

func requestEventIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if idx := strings.IndexByte(forwarded, ','); idx >= 0 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return strings.TrimSpace(forwarded)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func requestPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.Path
}
