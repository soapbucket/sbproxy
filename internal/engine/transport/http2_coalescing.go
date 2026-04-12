// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/platform/dns"
	"golang.org/x/net/http2"
)

// HTTP2CoalescingConfig configures HTTP/2 connection coalescing
type HTTP2CoalescingConfig struct {
	// Enable connection coalescing
	Enabled bool

	// Maximum idle connections per host
	MaxIdleConnsPerHost int

	// Idle connection timeout
	IdleConnTimeout time.Duration

	// Maximum lifetime for a connection
	MaxConnLifetime time.Duration

	// Allow coalescing based on IP address
	AllowIPBasedCoalescing bool

	// Allow coalescing based on certificate SAN
	AllowCertBasedCoalescing bool

	// Strict certificate validation
	StrictCertValidation bool
}

// HTTP2CoalescingTransport implements connection coalescing for HTTP/2
type HTTP2CoalescingTransport struct {
	config HTTP2CoalescingConfig

	// Base transport for HTTP/1.1 fallback
	baseTransport *http.Transport

	// Connection pool keyed by coalescing group
	connPool sync.Map // map[string]*coalescingGroup

	// TLS config for connections
	tlsConfig *tls.Config
}

// coalescingGroup represents a group of hosts that share a connection
type coalescingGroup struct {
	// Primary host for this group
	primaryHost string

	// All hosts in this group (including primary)
	hosts map[string]bool

	// Shared HTTP/2 client connection
	transport *http2.Transport

	// IP address for IP-based coalescing
	ipAddress net.IP

	// Certificate for cert-based coalescing
	cert *x509.Certificate

	// Creation time for lifetime tracking
	createdAt time.Time

	// Last used time for idle tracking
	lastUsed time.Time

	mu sync.RWMutex
}

// NewHTTP2CoalescingTransport creates a new HTTP/2 coalescing transport
func NewHTTP2CoalescingTransport(config HTTP2CoalescingConfig, tlsConfig *tls.Config) *HTTP2CoalescingTransport {
	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = 10
	}
	if config.IdleConnTimeout == 0 {
		config.IdleConnTimeout = 90 * time.Second
	}
	if config.MaxConnLifetime == 0 {
		config.MaxConnLifetime = 1 * time.Hour
	}

	// Create base transport for HTTP/1.1 fallback
	baseTransport := &http.Transport{
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		TLSClientConfig:     tlsConfig,
		DisableCompression:  false,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
	}

	t := &HTTP2CoalescingTransport{
		config:        config,
		baseTransport: baseTransport,
		tlsConfig:     tlsConfig,
	}

	// Start cleanup goroutine if enabled
	if config.Enabled {
		go t.cleanupLoop()
	}

	return t
}

// RoundTrip implements http.RoundTripper with connection coalescing
func (t *HTTP2CoalescingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.config.Enabled {
		return t.baseTransport.RoundTrip(req)
	}

	// Only coalesce HTTPS requests
	if req.URL.Scheme != "https" {
		return t.baseTransport.RoundTrip(req)
	}

	// Find or create coalescing group
	group, err := t.getOrCreateGroup(req)
	if err != nil {
		slog.Debug("failed to get coalescing group, using base transport",
			"error", err,
			"host", req.URL.Host)
		return t.baseTransport.RoundTrip(req)
	}

	// Check if group is expired
	if t.isGroupExpired(group) {
		slog.Debug("coalescing group expired, creating new one",
			"host", req.URL.Host)
		t.removeGroup(group)
		group, err = t.getOrCreateGroup(req)
		if err != nil {
			return t.baseTransport.RoundTrip(req)
		}
	}

	// Update last used time
	group.mu.Lock()
	group.lastUsed = time.Now()
	group.mu.Unlock()

	// Use coalesced connection
	resp, err := group.transport.RoundTrip(req)
	if err != nil {
		slog.Debug("coalesced request failed, falling back to base transport",
			"error", err.Error(),
			"host", req.URL.Host,
			"primary_host", group.primaryHost)
		// Fall back to base transport on error
		return t.baseTransport.RoundTrip(req)
	}

	return resp, err
}

// getOrCreateGroup finds an existing coalescing group or creates a new one
func (t *HTTP2CoalescingTransport) getOrCreateGroup(req *http.Request) (*coalescingGroup, error) {
	host := req.URL.Host

	// Check if host already has a group
	if val, ok := t.connPool.Load(host); ok {
		return val.(*coalescingGroup), nil
	}

	// Try to find a compatible group
	if t.config.AllowIPBasedCoalescing || t.config.AllowCertBasedCoalescing {
		if group := t.findCompatibleGroup(req); group != nil {
			// Add host to existing group
			group.mu.Lock()
			group.hosts[host] = true
			group.mu.Unlock()

			// Store reference
			t.connPool.Store(host, group)

			slog.Debug("coalesced connection to existing group",
				"host", host,
				"primary_host", group.primaryHost)

			return group, nil
		}
	}

	// Create new group
	return t.createGroup(req)
}

// findCompatibleGroup finds an existing group compatible with this request
func (t *HTTP2CoalescingTransport) findCompatibleGroup(req *http.Request) *coalescingGroup {
	host := req.URL.Host

	var compatibleGroup *coalescingGroup

	t.connPool.Range(func(key, value interface{}) bool {
		group := value.(*coalescingGroup)

		// Skip if this is the same host
		if key.(string) == host {
			return true
		}

		// Check IP-based coalescing
		if t.config.AllowIPBasedCoalescing && group.ipAddress != nil {
			if reqIP := t.resolveIP(host); reqIP != nil && reqIP.Equal(group.ipAddress) {
				compatibleGroup = group
				return false
			}
		}

		// Check certificate-based coalescing
		if t.config.AllowCertBasedCoalescing && group.cert != nil {
			if t.isCertValidForHost(group.cert, host) {
				compatibleGroup = group
				return false
			}
		}

		return true
	})

	return compatibleGroup
}

// createGroup creates a new coalescing group
func (t *HTTP2CoalescingTransport) createGroup(req *http.Request) (*coalescingGroup, error) {
	host := req.URL.Host

	// Create HTTP/2 transport
	http2Transport := &http2.Transport{
		TLSClientConfig: t.tlsConfig,
		AllowHTTP:       false,
		// Enable connection coalescing in http2 package
		StrictMaxConcurrentStreams: false,
	}

	group := &coalescingGroup{
		primaryHost: host,
		hosts:       make(map[string]bool),
		transport:   http2Transport,
		createdAt:   time.Now(),
		lastUsed:    time.Now(),
	}

	group.hosts[host] = true

	// Resolve IP if IP-based coalescing is enabled
	if t.config.AllowIPBasedCoalescing {
		if ip := t.resolveIP(host); ip != nil {
			group.ipAddress = ip
		}
	}

	// Get certificate if cert-based coalescing is enabled
	if t.config.AllowCertBasedCoalescing {
		if cert := t.getCertificate(host); cert != nil {
			group.cert = cert
		}
	}

	// Store in pool
	t.connPool.Store(host, group)

	slog.Debug("created new coalescing group",
		"host", host,
		"ip_coalescing", t.config.AllowIPBasedCoalescing,
		"cert_coalescing", t.config.AllowCertBasedCoalescing)

	return group, nil
}

// resolveIP resolves the IP address for a host using DNS cache
func (t *HTTP2CoalescingTransport) resolveIP(host string) net.IP {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Use DNS cache resolver if available
	resolver := dns.GetGlobalResolver()
	if resolver != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			slog.Debug("failed to resolve IP for coalescing",
				"host", host,
				"error", err)
			return nil
		}

		if len(ips) > 0 {
			return ips[0]
		}
		return nil
	}

	// Fallback to standard DNS lookup
	addrs, err := net.LookupIP(host)
	if err != nil {
		slog.Debug("failed to resolve IP for coalescing",
			"host", host,
			"error", err)
		return nil
	}

	if len(addrs) > 0 {
		return addrs[0]
	}

	return nil
}

// getCertificate retrieves the TLS certificate for a host
func (t *HTTP2CoalescingTransport) getCertificate(hostWithPort string) *x509.Certificate {
	// Add default port if not present
	addr := hostWithPort
	if _, _, err := net.SplitHostPort(hostWithPort); err != nil {
		addr = net.JoinHostPort(hostWithPort, "443")
	}

	// Establish TLS connection to get certificate
	conn, err := tls.Dial("tcp", addr, t.tlsConfig)
	if err != nil {
		slog.Debug("failed to get certificate for coalescing",
			"host", addr,
			"error", err)
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		return certs[0]
	}

	return nil
}

// isCertValidForHost checks if a certificate is valid for a given host
func (t *HTTP2CoalescingTransport) isCertValidForHost(cert *x509.Certificate, host string) bool {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Check CN
	if cert.Subject.CommonName == host {
		return true
	}

	// Check SANs
	for _, san := range cert.DNSNames {
		if matchHostname(san, host) {
			return true
		}
	}

	return false
}

// matchHostname matches a hostname against a pattern (supports wildcards)
func matchHostname(pattern, host string) bool {
	if pattern == host {
		return true
	}

	// Handle wildcard patterns
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Remove *
		if strings.HasSuffix(host, suffix) {
			// Ensure only one subdomain level
			remaining := strings.TrimSuffix(host, suffix)
			return !strings.Contains(remaining, ".")
		}
	}

	return false
}

// isGroupExpired checks if a coalescing group has expired
func (t *HTTP2CoalescingTransport) isGroupExpired(group *coalescingGroup) bool {
	group.mu.RLock()
	defer group.mu.RUnlock()

	now := time.Now()

	// Check max lifetime
	if now.Sub(group.createdAt) > t.config.MaxConnLifetime {
		return true
	}

	// Check idle timeout
	if now.Sub(group.lastUsed) > t.config.IdleConnTimeout {
		return true
	}

	return false
}

// removeGroup removes a coalescing group from the pool
func (t *HTTP2CoalescingTransport) removeGroup(group *coalescingGroup) {
	group.mu.Lock()
	hosts := make([]string, 0, len(group.hosts))
	for host := range group.hosts {
		hosts = append(hosts, host)
	}
	group.mu.Unlock()

	// Remove all hosts from pool
	for _, host := range hosts {
		t.connPool.Delete(host)
	}

	// Close transport
	if group.transport != nil {
		group.transport.CloseIdleConnections()
	}

	slog.Debug("removed coalescing group",
		"primary_host", group.primaryHost,
		"hosts", len(hosts))
}

// cleanupLoop periodically removes expired connections
func (t *HTTP2CoalescingTransport) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		t.cleanup()
	}
}

// cleanup removes expired coalescing groups
func (t *HTTP2CoalescingTransport) cleanup() {
	var expiredGroups []*coalescingGroup
	seenGroups := make(map[*coalescingGroup]bool)

	t.connPool.Range(func(key, value interface{}) bool {
		group := value.(*coalescingGroup)

		// Skip if already checked
		if seenGroups[group] {
			return true
		}
		seenGroups[group] = true

		if t.isGroupExpired(group) {
			expiredGroups = append(expiredGroups, group)
		}

		return true
	})

	// Remove expired groups
	for _, group := range expiredGroups {
		t.removeGroup(group)
	}

	if len(expiredGroups) > 0 {
		slog.Debug("cleaned up expired coalescing groups", "count", len(expiredGroups))
	}
}

// CloseIdleConnections closes idle connections
func (t *HTTP2CoalescingTransport) CloseIdleConnections() {
	t.baseTransport.CloseIdleConnections()

	t.connPool.Range(func(key, value interface{}) bool {
		group := value.(*coalescingGroup)
		if group.transport != nil {
			group.transport.CloseIdleConnections()
		}
		return true
	})
}

// GetStats returns statistics about connection coalescing
func (t *HTTP2CoalescingTransport) GetStats() CoalescingStats {
	stats := CoalescingStats{
		Groups: make(map[string]GroupStats),
	}

	seenGroups := make(map[*coalescingGroup]bool)

	t.connPool.Range(func(key, value interface{}) bool {
		group := value.(*coalescingGroup)
		_ = key.(string) // host key, tracked for completeness

		// Only count each group once
		if !seenGroups[group] {
			seenGroups[group] = true
			stats.TotalGroups++

			group.mu.RLock()
			groupStats := GroupStats{
				PrimaryHost: group.primaryHost,
				Hosts:       make([]string, 0, len(group.hosts)),
				CreatedAt:   group.createdAt,
				LastUsed:    group.lastUsed,
				Age:         time.Since(group.createdAt),
				IdleTime:    time.Since(group.lastUsed),
			}
			for h := range group.hosts {
				groupStats.Hosts = append(groupStats.Hosts, h)
			}
			group.mu.RUnlock()

			stats.Groups[group.primaryHost] = groupStats
			stats.TotalHosts += len(groupStats.Hosts)
		} else {
			// This host is coalesced
			stats.CoalescedHosts++
		}

		stats.TotalHostEntries++

		return true
	})

	return stats
}

// CoalescingStats represents connection coalescing statistics
type CoalescingStats struct {
	TotalGroups      int
	TotalHosts       int
	CoalescedHosts   int
	TotalHostEntries int
	Groups           map[string]GroupStats
}

// GroupStats represents statistics for a single coalescing group
type GroupStats struct {
	PrimaryHost string
	Hosts       []string
	CreatedAt   time.Time
	LastUsed    time.Time
	Age         time.Duration
	IdleTime    time.Duration
}

// String returns a formatted string representation of stats
func (s CoalescingStats) String() string {
	return fmt.Sprintf("Groups: %d, Total Hosts: %d, Coalesced: %d, Savings: %.1f%%",
		s.TotalGroups,
		s.TotalHosts,
		s.CoalescedHosts,
		float64(s.CoalescedHosts)/float64(s.TotalHostEntries)*100)
}
