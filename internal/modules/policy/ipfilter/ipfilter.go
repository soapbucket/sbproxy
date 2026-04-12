// Package ipfilter registers the ip_filtering policy.
package ipfilter

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
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("ip_filtering", New)
}

// Config holds configuration for the ip_filtering policy.
type Config struct {
	Type              string            `json:"type"`
	Disabled          bool              `json:"disabled,omitempty"`
	Whitelist         []string          `json:"whitelist,omitempty"`
	Blacklist         []string          `json:"blacklist,omitempty"`
	Action            string            `json:"action,omitempty"`
	TemporaryBans     map[string]string `json:"temporary_bans,omitempty"`
	DynamicBlocklist  []string          `json:"dynamic_blocklist,omitempty"`
	BlocklistTTL      duration          `json:"blocklist_ttl,omitempty"`
	TrustedProxyCIDRs []string          `json:"trusted_proxy_cidrs,omitempty"`
}

// duration wraps time.Duration for JSON unmarshaling from string.
type duration struct {
	Duration time.Duration
}

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// New creates a new ip_filtering policy enforcer.
func New(data json.RawMessage) (plugin.PolicyEnforcer, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	p := &ipFilterPolicy{
		cfg:              cfg,
		temporaryBans:    make(map[string]time.Time),
		dynamicBlocklist: make(map[string]time.Time),
	}

	// Parse whitelist.
	p.whitelist = make([]*net.IPNet, 0, len(cfg.Whitelist))
	for _, cidr := range cfg.Whitelist {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			p.whitelist = append(p.whitelist, ipNet)
		} else if ip := net.ParseIP(cidr); ip != nil {
			suffix := "/32"
			if strings.Contains(cidr, ":") {
				suffix = "/128"
			}
			_, ipNet, _ := net.ParseCIDR(cidr + suffix)
			p.whitelist = append(p.whitelist, ipNet)
		}
	}

	// Parse blacklist.
	p.blacklist = make([]*net.IPNet, 0, len(cfg.Blacklist))
	for _, cidr := range cfg.Blacklist {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			p.blacklist = append(p.blacklist, ipNet)
		} else if ip := net.ParseIP(cidr); ip != nil {
			suffix := "/32"
			if strings.Contains(cidr, ":") {
				suffix = "/128"
			}
			_, ipNet, _ := net.ParseCIDR(cidr + suffix)
			p.blacklist = append(p.blacklist, ipNet)
		}
	}

	// Parse trusted proxy CIDRs (policy config first, then global settings).
	trustedCIDRs := cfg.TrustedProxyCIDRs
	if len(trustedCIDRs) == 0 {
		trustedCIDRs = settings.Global.TrustedProxyCIDRs
	}
	p.trustedProxies = make([]*net.IPNet, 0)
	for _, cidr := range trustedCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			p.trustedProxies = append(p.trustedProxies, ipNet)
		} else if ip := net.ParseIP(cidr); ip != nil {
			suffix := "/32"
			if strings.Contains(cidr, ":") {
				suffix = "/128"
			}
			_, ipNet, _ := net.ParseCIDR(cidr + suffix)
			p.trustedProxies = append(p.trustedProxies, ipNet)
		}
	}

	// Parse temporary bans.
	if cfg.TemporaryBans != nil {
		now := time.Now()
		for ip, durationStr := range cfg.TemporaryBans {
			dur, err := time.ParseDuration(durationStr)
			if err != nil {
				return nil, fmt.Errorf("invalid duration for temporary ban on %s: %w", ip, err)
			}
			p.temporaryBans[ip] = now.Add(dur)
		}
	}

	return p, nil
}

type ipFilterPolicy struct {
	cfg              *Config
	whitelist        []*net.IPNet
	blacklist        []*net.IPNet
	trustedProxies   []*net.IPNet
	temporaryBans    map[string]time.Time
	dynamicBlocklist map[string]time.Time
	mu               sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
}

func (p *ipFilterPolicy) Type() string { return "ip_filtering" }

// InitPlugin implements plugin.Initable.
func (p *ipFilterPolicy) InitPlugin(_ plugin.PluginContext) error {
	p.ctx, p.cancel = context.WithCancel(context.Background())
	go p.cleanup()
	if len(p.cfg.DynamicBlocklist) > 0 {
		go p.loadDynamicBlocklist()
	}
	return nil
}

func (p *ipFilterPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := getClientIPWithTrustedProxies(r, p.trustedProxies)
		if clientIP == "" {
			if len(p.blacklist) > 0 && (p.cfg.Action == "" || p.cfg.Action == "block") {
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

		// Whitelist check.
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

		// Temporary bans check.
		p.mu.RLock()
		if expires, banned := p.temporaryBans[clientIP]; banned {
			if time.Now().Before(expires) {
				p.mu.RUnlock()
				reqctx.RecordPolicyViolation(r.Context(), "ip_filter", fmt.Sprintf("IP address temporarily banned until %s", expires.Format(time.RFC3339)))
				http.Error(w, fmt.Sprintf("IP address temporarily banned until %s", expires.Format(time.RFC3339)), http.StatusForbidden)
				return
			}
			p.mu.RUnlock()
			p.mu.Lock()
			delete(p.temporaryBans, clientIP)
			p.mu.Unlock()
		} else {
			p.mu.RUnlock()
		}

		// Dynamic blocklist check.
		p.mu.RLock()
		if expires, blocked := p.dynamicBlocklist[clientIP]; blocked {
			if time.Now().Before(expires) {
				p.mu.RUnlock()
				reqctx.RecordPolicyViolation(r.Context(), "ip_filter", "IP address is on dynamic blocklist")
				http.Error(w, "IP address is on dynamic blocklist", http.StatusForbidden)
				return
			}
			p.mu.RUnlock()
			p.mu.Lock()
			delete(p.dynamicBlocklist, clientIP)
			p.mu.Unlock()
		} else {
			p.mu.RUnlock()
		}

		// Static blacklist check.
		if len(p.blacklist) > 0 {
			for _, ipNet := range p.blacklist {
				if ipNet.Contains(parsedIP) {
					action := p.cfg.Action
					if action == "" {
						action = "block"
					}
					if action == "block" {
						reqctx.RecordPolicyViolation(r.Context(), "ip_filter", "IP address is blacklisted")
						http.Error(w, "IP address is blacklisted", http.StatusForbidden)
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (p *ipFilterPolicy) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			for ip, expires := range p.temporaryBans {
				if now.After(expires) {
					delete(p.temporaryBans, ip)
				}
			}
			for ip, expires := range p.dynamicBlocklist {
				if now.After(expires) {
					delete(p.dynamicBlocklist, ip)
				}
			}
			p.mu.Unlock()
		}
	}
}

func (p *ipFilterPolicy) loadDynamicBlocklist() {
	ttl := 24 * time.Hour
	if p.cfg.BlocklistTTL.Duration > 0 {
		ttl = p.cfg.BlocklistTTL.Duration
	}

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

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

func (p *ipFilterPolicy) fetchDynamicBlocklists(ttl time.Duration) {
	expires := time.Now().Add(ttl)

	for _, blocklistURL := range p.cfg.DynamicBlocklist {
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

		scanner := bufio.NewScanner(resp.Body)
		addedCount := 0

		p.mu.Lock()
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "/") {
				if _, _, err := net.ParseCIDR(line); err == nil {
					p.dynamicBlocklist[line] = expires
					addedCount++
				}
			} else {
				if net.ParseIP(line) != nil {
					p.dynamicBlocklist[line] = expires
					addedCount++
				}
			}
		}
		p.mu.Unlock()

		resp.Body.Close()
		slog.Info("blocklist fetched", "url", blocklistURL, "entries_added", addedCount)
	}
}

// getClientIPWithTrustedProxies extracts the client IP, only trusting headers from allowed proxy CIDRs.
func getClientIPWithTrustedProxies(req *http.Request, trustedProxies []*net.IPNet) string {
	sourceIP := req.RemoteAddr
	if sourceIP != "" {
		if host, _, err := net.SplitHostPort(sourceIP); err == nil {
			sourceIP = host
		}
	}

	sourceParsedIP := net.ParseIP(sourceIP)

	isTrusted := func() bool {
		if len(trustedProxies) == 0 {
			return false
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

	if isTrusted() {
		if xri := req.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
	}

	if req.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err == nil {
			return host
		}
		return req.RemoteAddr
	}

	return ""
}
