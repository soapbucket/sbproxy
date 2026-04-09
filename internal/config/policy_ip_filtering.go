// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
	"github.com/soapbucket/sbproxy/internal/loader/settings"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func init() {
	policyLoaderFns[PolicyTypeIPFiltering] = NewIPFilteringPolicy
}

// IPFilteringPolicyConfig implements PolicyConfig for IP filtering
type IPFilteringPolicyConfig struct {
	IPFilteringPolicy

	// Internal
	config              *Config
	whitelist           []*net.IPNet
	blacklist           []*net.IPNet
	trustedProxies      []*net.IPNet
	temporaryBans       map[string]time.Time // IP -> expiration time (local fallback)
	dynamicBlocklist    map[string]time.Time // IP -> expiration time (local fallback)
	stateStore          PolicyStateStore     // External state store for distributed deployments (nil = local only)
	mu                  sync.RWMutex
	ctx                 context.Context
	cancel              context.CancelFunc
}

// NewIPFilteringPolicy creates a new IP filtering policy config
func NewIPFilteringPolicy(data []byte) (PolicyConfig, error) {
	cfg := &IPFilteringPolicyConfig{
		temporaryBans:    make(map[string]time.Time),
		dynamicBlocklist: make(map[string]time.Time),
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Parse whitelist
	cfg.whitelist = make([]*net.IPNet, 0, len(cfg.Whitelist))
	for _, cidr := range cfg.Whitelist {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			cfg.whitelist = append(cfg.whitelist, ipNet)
		} else if ip := net.ParseIP(cidr); ip != nil {
			// Single IP address - detect IPv6 vs IPv4
			suffix := "/32"
			if strings.Contains(cidr, ":") {
				suffix = "/128"
			}
			_, ipNet, _ := net.ParseCIDR(cidr + suffix)
			cfg.whitelist = append(cfg.whitelist, ipNet)
		}
	}

	// Parse blacklist
	cfg.blacklist = make([]*net.IPNet, 0, len(cfg.Blacklist))
	for _, cidr := range cfg.Blacklist {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			cfg.blacklist = append(cfg.blacklist, ipNet)
		} else if ip := net.ParseIP(cidr); ip != nil {
			// Single IP address - detect IPv6 vs IPv4
			suffix := "/32"
			if strings.Contains(cidr, ":") {
				suffix = "/128"
			}
			_, ipNet, _ := net.ParseCIDR(cidr + suffix)
			cfg.blacklist = append(cfg.blacklist, ipNet)
		}
	}

	// Parse trusted proxy CIDRs (use policy config first, then fall back to global settings)
	cfg.trustedProxies = make([]*net.IPNet, 0)
	trustedCIDRs := cfg.TrustedProxyCIDRs
	if len(trustedCIDRs) == 0 {
		trustedCIDRs = settings.Global.TrustedProxyCIDRs
	}
	for _, cidr := range trustedCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			cfg.trustedProxies = append(cfg.trustedProxies, ipNet)
		} else if ip := net.ParseIP(cidr); ip != nil {
			// Single IP address - detect IPv6 vs IPv4
			suffix := "/32"
			if strings.Contains(cidr, ":") {
				suffix = "/128"
			}
			_, ipNet, _ := net.ParseCIDR(cidr + suffix)
			cfg.trustedProxies = append(cfg.trustedProxies, ipNet)
		}
	}

	// Parse temporary bans
	if cfg.TemporaryBans != nil {
		now := time.Now()
		for ip, durationStr := range cfg.TemporaryBans {
			duration, err := time.ParseDuration(durationStr)
			if err != nil {
				return nil, fmt.Errorf("invalid duration for temporary ban on %s: %w", ip, err)
			}
			cfg.temporaryBans[ip] = now.Add(duration)

			// Persist to external state store if available
			if cfg.stateStore != nil {
				storeKey := "tempban:" + ip
				_ = cfg.stateStore.Set(context.Background(), storeKey, []byte(durationStr), duration)
			}
		}
	}

	return cfg, nil
}

// SetStateStore sets an external policy state store for distributed deployments.
// When set, temporary bans and dynamic blocklist entries are persisted externally
// so that all proxy instances share the same view. If not called, all state remains
// in local maps (the default, backwards-compatible behavior).
func (p *IPFilteringPolicyConfig) SetStateStore(store PolicyStateStore) {
	p.stateStore = store
}

// Init initializes the policy config
func (p *IPFilteringPolicyConfig) Init(config *Config) error {
	p.config = config
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Start cleanup goroutine for temporary bans
	go p.cleanup()

	// Load dynamic blocklist if configured
	if len(p.DynamicBlocklist) > 0 {
		go p.loadDynamicBlocklist()
	}

	return nil
}

// cleanup removes expired temporary bans and dynamic blocklist entries
func (p *IPFilteringPolicyConfig) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()

			// Clean up expired temporary bans
			for ip, expires := range p.temporaryBans {
				if now.After(expires) {
					delete(p.temporaryBans, ip)
				}
			}

			// Clean up expired dynamic blocklist entries
			for ip, expires := range p.dynamicBlocklist {
				if now.After(expires) {
					delete(p.dynamicBlocklist, ip)
				}
			}

			p.mu.Unlock()
		}
	}
}

// loadDynamicBlocklist loads IPs from configured URLs
func (p *IPFilteringPolicyConfig) loadDynamicBlocklist() {
	// Parse TTL
	ttl := 24 * time.Hour
	if p.BlocklistTTL.Duration > 0 {
		ttl = p.BlocklistTTL.Duration
	}

	// Load blocklists periodically
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Load immediately
	p.fetchDynamicBlocklists(ttl)

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.fetchDynamicBlocklists(ttl)
		}
	}
}

// fetchDynamicBlocklists fetches IPs from configured URLs.
// Each URL is protected by a circuit breaker from the default registry.
func (p *IPFilteringPolicyConfig) fetchDynamicBlocklists(ttl time.Duration) {
	expires := time.Now().Add(ttl)

	for _, blocklistURL := range p.DynamicBlocklist {
		cb := circuitbreaker.DefaultRegistry.GetOrCreate(
			"blocklist:"+blocklistURL,
			circuitbreaker.Config{
				FailureThreshold: 3,
				SuccessThreshold: 1,
				Timeout:          5 * time.Minute,
			},
		)

		var resp *http.Response
		fetchErr := cb.Call(func() error {
			fetchCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, blocklistURL, nil)
			if err != nil {
				return fmt.Errorf("failed to create blocklist request: %w", err)
			}

			var doErr error
			resp, doErr = http.DefaultClient.Do(req)
			return doErr
		})

		if fetchErr != nil {
			slog.Warn("failed to fetch blocklist", "url", blocklistURL, "error", fetchErr)
			continue
		}

		// Parse response: could be plain IPs (one per line), CIDR, or CSV
		scanner := bufio.NewScanner(resp.Body)
		addedCount := 0

		p.mu.Lock()
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// Skip comments and empty lines
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Parse as IP address or CIDR
			if strings.Contains(line, "/") {
				// CIDR notation
				if _, _, err := net.ParseCIDR(line); err == nil {
					p.dynamicBlocklist[line] = expires
					addedCount++
					// Persist to external state store
					if p.stateStore != nil {
						storeKey := "dynblock:" + line
						_ = p.stateStore.Set(p.ctx, storeKey, []byte("1"), ttl)
					}
				}
			} else {
				// Single IP address
				if net.ParseIP(line) != nil {
					p.dynamicBlocklist[line] = expires
					addedCount++
					// Persist to external state store
					if p.stateStore != nil {
						storeKey := "dynblock:" + line
						_ = p.stateStore.Set(p.ctx, storeKey, []byte("1"), ttl)
					}
				}
			}
		}
		p.mu.Unlock()

		resp.Body.Close()

		slog.Info("blocklist fetched", "url", blocklistURL, "entries_added", addedCount)
	}
}

// Apply implements the middleware pattern for IP filtering
func (p *IPFilteringPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := GetClientIPFromRequestWithTrustedProxies(r, p.trustedProxies)
		if clientIP == "" {
			// If we can't determine IP, default to blocking if blacklist exists
			if len(p.blacklist) > 0 && (p.Action == "" || p.Action == "block") {
				reqctx.RecordPolicyViolation(r.Context(), "ip_filter", "IP address could not be determined")
				http.Error(w, "IP address could not be determined", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		parsedIP := net.ParseIP(clientIP)
		if parsedIP == nil {
			reqctx.RecordPolicyViolation(r.Context(), "ip_filter", "Invalid IP address")
			http.Error(w, "Invalid IP address", http.StatusBadRequest)
			return
		}

		// Check whitelist first (whitelist takes precedence)
		if len(p.whitelist) > 0 {
			whitelisted := false
			for _, ipNet := range p.whitelist {
				if ipNet.Contains(parsedIP) {
					whitelisted = true
					break
				}
			}
			if !whitelisted {
				reqctx.RecordPolicyViolation(r.Context(), "ip_filter", "IP address not whitelisted")
				http.Error(w, "IP address not whitelisted", http.StatusForbidden)
				return
			}
		}

		// Check temporary bans - external state store first, then local
		if p.stateStore != nil {
			storeKey := "tempban:" + clientIP
			data, err := p.stateStore.Get(r.Context(), storeKey)
			if err == nil && data != nil {
				reqctx.RecordPolicyViolation(r.Context(), "ip_filter", "IP address temporarily banned")
				http.Error(w, "IP address temporarily banned", http.StatusForbidden)
				return
			}
		}
		p.mu.RLock()
		if expires, banned := p.temporaryBans[clientIP]; banned {
			if time.Now().Before(expires) {
				p.mu.RUnlock()
				reqctx.RecordPolicyViolation(r.Context(), "ip_filter", fmt.Sprintf("IP address temporarily banned until %s", expires.Format(time.RFC3339)))
				http.Error(w, fmt.Sprintf("IP address temporarily banned until %s", expires.Format(time.RFC3339)), http.StatusForbidden)
				return
			}
			// Ban expired, remove it
			p.mu.RUnlock()
			p.mu.Lock()
			delete(p.temporaryBans, clientIP)
			p.mu.Unlock()
		} else {
			p.mu.RUnlock()
		}

		// Check dynamic blocklist - external state store first, then local
		if p.stateStore != nil {
			storeKey := "dynblock:" + clientIP
			data, err := p.stateStore.Get(r.Context(), storeKey)
			if err == nil && data != nil {
				reqctx.RecordPolicyViolation(r.Context(), "ip_filter", "IP address is on dynamic blocklist")
				http.Error(w, "IP address is on dynamic blocklist", http.StatusForbidden)
				return
			}
		}
		p.mu.RLock()
		if expires, blocked := p.dynamicBlocklist[clientIP]; blocked {
			if time.Now().Before(expires) {
				p.mu.RUnlock()
				reqctx.RecordPolicyViolation(r.Context(), "ip_filter", "IP address is on dynamic blocklist")
				http.Error(w, "IP address is on dynamic blocklist", http.StatusForbidden)
				return
			}
			// Block expired, remove it
			p.mu.RUnlock()
			p.mu.Lock()
			delete(p.dynamicBlocklist, clientIP)
			p.mu.Unlock()
		} else {
			p.mu.RUnlock()
		}

		// Check static blacklist
		if len(p.blacklist) > 0 {
			for _, ipNet := range p.blacklist {
				if ipNet.Contains(parsedIP) {
					action := p.Action
					if action == "" {
						action = "block"
					}
					if action == "block" {
						reqctx.RecordPolicyViolation(r.Context(), "ip_filter", "IP address is blacklisted")
						http.Error(w, "IP address is blacklisted", http.StatusForbidden)
						return
					}
					// If action is "allow", we still allow but could log it
				}
			}
		}

		// All checks passed, continue to next handler
		next.ServeHTTP(w, r)
	})
}

// GetClientIPFromRequest extracts the client IP from the request
// Deprecated: Use policy-specific method instead
func GetClientIPFromRequest(req *http.Request) string {
	return GetClientIPFromRequestWithTrustedProxies(req, nil)
}

// GetClientIPFromRequestWithTrustedProxies extracts the client IP, only trusting headers from allowed proxy CIDRs
func GetClientIPFromRequestWithTrustedProxies(req *http.Request, trustedProxies []*net.IPNet) string {
	sourceIP := req.RemoteAddr
	if sourceIP != "" {
		if host, _, err := net.SplitHostPort(sourceIP); err == nil {
			sourceIP = host
		}
	}

	sourceParsedIP := net.ParseIP(sourceIP)

	// Helper to check if source IP is in trusted proxies
	isTrusted := func() bool {
		if len(trustedProxies) == 0 {
			return false // No trusted proxies configured, don't trust headers
		}
		if sourceParsedIP == nil {
			return false
		}
		for _, ipNet := range trustedProxies {
			if ipNet.Contains(sourceParsedIP) {
				return true
			}
		}
		return false
	}

	// Only trust X-Real-IP/X-Forwarded-For if source is in trusted proxies
	if isTrusted() {
		// Check X-Real-IP header first
		if xri := req.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}

		// Check X-Forwarded-For header
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
	}

	// Use RemoteAddr (extract IP from "host:port" format)
	if req.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err == nil {
			return host
		}
		// If SplitHostPort fails, try to use RemoteAddr as-is (might be just IP)
		return req.RemoteAddr
	}

	return ""
}

