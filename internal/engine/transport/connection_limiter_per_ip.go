// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/ratelimit"
)

// PerIPConnectionLimiterConfig configures per-IP connection limiting
type PerIPConnectionLimiterConfig struct {
	// MaxConnectionsPerIP limits concurrent connections per IP
	MaxConnectionsPerIP int `json:"max_connections_per_ip,omitempty"`

	// ConnectionsPerSecondPerIP limits connection rate per IP
	ConnectionsPerSecondPerIP int `json:"connections_per_second_per_ip,omitempty"`

	// MaxConnectionDuration limits how long a single connection can be active
	MaxConnectionDuration time.Duration `json:"max_connection_duration,omitempty"`

	// CleanupInterval specifies how often to clean up old connection tracking data
	CleanupInterval time.Duration `json:"cleanup_interval,omitempty"`

	// WhitelistCIDRs are IP ranges exempt from rate limiting
	WhitelistCIDRs []string `json:"whitelist_cidrs,omitempty"`
}

// PerIPConnectionLimiter limits connections on a per-IP basis
type PerIPConnectionLimiter struct {
	http.RoundTripper

	config         *PerIPConnectionLimiterConfig
	rateLimiter    *ratelimit.DistributedRateLimiter
	connectionMap  map[string]*ipConnectionInfo
	mutex          sync.RWMutex
	whitelist      []*net.IPNet
	cleanupStop    chan struct{}
	cleanupDone    chan struct{}
	metricsAllowed int64
	metricsDenied  int64
}

// ipConnectionInfo tracks connection info for a single IP
type ipConnectionInfo struct {
	activeConnections int
	connectionTimes   []time.Time
	mu                sync.Mutex
}

// NewPerIPConnectionLimiter creates a new per-IP connection limiter
func NewPerIPConnectionLimiter(tr http.RoundTripper, config *PerIPConnectionLimiterConfig, rateLimiter *ratelimit.DistributedRateLimiter) (*PerIPConnectionLimiter, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	limiter := &PerIPConnectionLimiter{
		RoundTripper:  tr,
		config:        config,
		rateLimiter:   rateLimiter,
		connectionMap: make(map[string]*ipConnectionInfo),
		cleanupStop:   make(chan struct{}),
		cleanupDone:   make(chan struct{}),
	}

	// Parse whitelist CIDRs
	if len(config.WhitelistCIDRs) > 0 {
		for _, cidr := range config.WhitelistCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
			}
			limiter.whitelist = append(limiter.whitelist, ipNet)
		}
	}

	// Set default cleanup interval if not specified
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 5 * time.Minute
	}

	// Set default max connection duration if not specified
	if config.MaxConnectionDuration == 0 {
		config.MaxConnectionDuration = 5 * time.Minute
	}

	// Start cleanup goroutine
	go limiter.cleanupRoutine()

	return limiter, nil
}

// RoundTrip implements per-IP connection limiting logic
func (l *PerIPConnectionLimiter) RoundTrip(req *http.Request) (*http.Response, error) {
	// Extract client IP
	clientIP := l.extractClientIP(req)
	if clientIP == "" {
		// Can't determine IP, allow request
		return l.RoundTripper.RoundTrip(req)
	}

	// Check whitelist
	if l.isWhitelisted(clientIP) {
		return l.RoundTripper.RoundTrip(req)
	}

	// Check rate limits
	if !l.checkRateLimits(req.Context(), clientIP) {
		l.mutex.Lock()
		l.metricsDenied++
		l.mutex.Unlock()

		slog.Warn("connection rate limit exceeded",
			"client_ip", clientIP,
			"max_connections", l.config.MaxConnectionsPerIP,
			"max_rate", l.config.ConnectionsPerSecondPerIP)

		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     make(http.Header),
			Request:    req,
			Body:       http.NoBody,
		}, nil
	}

	// Acquire connection slot
	if !l.acquireConnection(clientIP) {
		l.mutex.Lock()
		l.metricsDenied++
		l.mutex.Unlock()

		slog.Warn("connection limit exceeded",
			"client_ip", clientIP,
			"max_connections", l.config.MaxConnectionsPerIP)

		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     make(http.Header),
			Request:    req,
			Body:       http.NoBody,
		}, nil
	}

	l.mutex.Lock()
	l.metricsAllowed++
	l.mutex.Unlock()

	// Release connection when done
	defer l.releaseConnection(clientIP)

	// Apply connection duration timeout if configured
	if l.config.MaxConnectionDuration > 0 {
		ctx, cancel := context.WithTimeout(req.Context(), l.config.MaxConnectionDuration)
		defer cancel()
		req = req.WithContext(ctx)
	}

	// Make the actual request
	return l.RoundTripper.RoundTrip(req)
}

// extractClientIP extracts the client IP from the request
func (l *PerIPConnectionLimiter) extractClientIP(req *http.Request) string {
	// Try X-Forwarded-For header first
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := parseXForwardedFor(xff)
		if len(ips) > 0 {
			return ips[0]
		}
	}

	// Try X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// parseXForwardedFor parses the X-Forwarded-For header
func parseXForwardedFor(xff string) []string {
	var ips []string
	for _, ip := range splitComma(xff) {
		ip = trimSpace(ip)
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

// Helper functions to avoid importing strings package
func splitComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// isWhitelisted checks if an IP is whitelisted
func (l *PerIPConnectionLimiter) isWhitelisted(clientIP string) bool {
	if len(l.whitelist) == 0 {
		return false
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, ipNet := range l.whitelist {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// checkRateLimits checks if the connection rate is within limits
func (l *PerIPConnectionLimiter) checkRateLimits(ctx context.Context, clientIP string) bool {
	// Check connection rate per second if configured
	if l.config.ConnectionsPerSecondPerIP > 0 {
		if l.rateLimiter != nil {
			// Use distributed rate limiter
			key := fmt.Sprintf("conn:%s", clientIP)
			result, err := l.rateLimiter.Allow(ctx, key, l.config.ConnectionsPerSecondPerIP, time.Second)
			if err != nil {
				slog.Error("rate limiter error", "error", err, "client_ip", clientIP)
				// On error, allow request (fail open)
				return true
			}
			return result.Allowed
		}
	}

	return true
}

// acquireConnection attempts to acquire a connection slot for an IP
func (l *PerIPConnectionLimiter) acquireConnection(clientIP string) bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	info, exists := l.connectionMap[clientIP]
	if !exists {
		info = &ipConnectionInfo{
			connectionTimes: make([]time.Time, 0),
		}
		l.connectionMap[clientIP] = info
	}

	// Check max connections per IP
	if l.config.MaxConnectionsPerIP > 0 {
		if info.activeConnections >= l.config.MaxConnectionsPerIP {
			return false
		}
	}

	info.activeConnections++
	info.connectionTimes = append(info.connectionTimes, time.Now())
	return true
}

// releaseConnection releases a connection slot for an IP
func (l *PerIPConnectionLimiter) releaseConnection(clientIP string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if info, exists := l.connectionMap[clientIP]; exists {
		info.activeConnections--
		if info.activeConnections <= 0 {
			// Clean up if no active connections
			delete(l.connectionMap, clientIP)
		}
	}
}

// cleanupRoutine periodically cleans up old connection tracking data
func (l *PerIPConnectionLimiter) cleanupRoutine() {
	ticker := time.NewTicker(l.config.CleanupInterval)
	defer ticker.Stop()
	defer close(l.cleanupDone)

	for {
		select {
		case <-ticker.C:
			l.cleanup()
		case <-l.cleanupStop:
			return
		}
	}
}

// cleanup removes stale connection tracking data
func (l *PerIPConnectionLimiter) cleanup() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.config.CleanupInterval)

	for ip, info := range l.connectionMap {
		// Remove old connection times
		info.mu.Lock()
		var validTimes []time.Time
		for _, t := range info.connectionTimes {
			if t.After(cutoff) {
				validTimes = append(validTimes, t)
			}
		}
		info.connectionTimes = validTimes

		// Remove IPs with no active connections and no recent history
		if info.activeConnections == 0 && len(info.connectionTimes) == 0 {
			delete(l.connectionMap, ip)
		}
		info.mu.Unlock()
	}
}

// Close stops the cleanup routine
func (l *PerIPConnectionLimiter) Close() error {
	close(l.cleanupStop)
	<-l.cleanupDone
	return nil
}

// GetMetrics returns current metrics
func (l *PerIPConnectionLimiter) GetMetrics() (allowed, denied int64) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.metricsAllowed, l.metricsDenied
}

// GetActiveConnectionsForIP returns the number of active connections for a given IP
func (l *PerIPConnectionLimiter) GetActiveConnectionsForIP(clientIP string) int {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if info, exists := l.connectionMap[clientIP]; exists {
		return info.activeConnections
	}
	return 0
}

// GetTotalTrackedIPs returns the total number of IPs being tracked
func (l *PerIPConnectionLimiter) GetTotalTrackedIPs() int {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return len(l.connectionMap)
}
