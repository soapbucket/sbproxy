// Package dns implements a DNS resolution cache to reduce lookup latency for upstream hosts.
package dns

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// Resolver wraps net.Resolver with DNS caching
type Resolver struct {
	base    *net.Resolver
	cache   *Cache
	enabled bool
}

// NewResolver creates a new DNS resolver with caching
func NewResolver(cache *Cache) *Resolver {
	if cache == nil {
		// Return resolver without caching if cache is disabled
		return &Resolver{
			base:    net.DefaultResolver,
			cache:   nil,
			enabled: false,
		}
	}

	return &Resolver{
		base:    net.DefaultResolver,
		cache:   cache,
		enabled: true,
	}
}

// LookupIP looks up IP addresses for the given hostname
func (r *Resolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if !r.enabled || r.cache == nil {
		return r.base.LookupIP(ctx, network, host)
	}

	// Check cache first
	if entry, found := r.cache.Get(host); found {
		if entry.IsNegative {
			r.cache.RecordHit()
			metric.DNSCacheHit()
			return nil, &net.DNSError{
				Err:        "no such host",
				Name:       host,
				Server:     "",
				IsNotFound: true,
			}
		}
		r.cache.RecordHit()
		metric.DNSCacheHit()
		slog.Debug("DNS cache hit", "hostname", host, "ips", len(entry.IPs))
		return entry.IPs, nil
	}

	r.cache.RecordMiss()
	metric.DNSCacheMiss()

	// Perform DNS lookup and measure resolution time
	startTime := time.Now()
	ips, err := r.base.LookupIP(ctx, network, host)
	duration := time.Since(startTime).Seconds()
	
	// Record DNS resolution time metric
	result := "success"
	if err != nil {
		result = "error"
	}
	metric.DNSResolutionTime(host, result, duration)

	// Cache the result (positive or negative)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// Cache negative response
			r.cache.Put(host, nil, 0, true)
			slog.Debug("DNS lookup failed, cached negative", "hostname", host, "error", err)
		} else {
			// For other errors, check if we can serve stale entry
			if entry, found := r.cache.Get(host); found && entry.IsStale() {
				slog.Debug("DNS lookup failed, serving stale entry", "hostname", host, "error", err)
				return entry.IPs, nil
			}
		}
		return nil, err
	}

	// Cache positive response
	// Try to get TTL from context or use default
	ttl := 0 * time.Second // Will use default TTL
	r.cache.Put(host, ips, ttl, false)
	slog.Debug("DNS lookup successful, cached", "hostname", host, "ips", len(ips))

	return ips, nil
}

// LookupHost looks up host addresses for the given hostname
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if !r.enabled || r.cache == nil {
		return r.base.LookupHost(ctx, host)
	}

	// Check cache first
	if entry, found := r.cache.Get(host); found {
		if entry.IsNegative {
			r.cache.RecordHit()
			metric.DNSCacheHit()
			return nil, &net.DNSError{
				Err:        "no such host",
				Name:       host,
				Server:     "",
				IsNotFound: true,
			}
		}
		r.cache.RecordHit()
		metric.DNSCacheHit()
		// Convert IPs to strings
		addrs := make([]string, len(entry.IPs))
		for i, ip := range entry.IPs {
			addrs[i] = ip.String()
		}
		slog.Debug("DNS cache hit (LookupHost)", "hostname", host, "addrs", len(addrs))
		return addrs, nil
	}

	r.cache.RecordMiss()
	metric.DNSCacheMiss()

	// Perform DNS lookup and measure resolution time
	startTime := time.Now()
	addrs, err := r.base.LookupHost(ctx, host)
	duration := time.Since(startTime).Seconds()
	
	// Record DNS resolution time metric
	result := "success"
	if err != nil {
		result = "error"
	}
	metric.DNSResolutionTime(host, result, duration)

	// Cache the result
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// Cache negative response
			r.cache.Put(host, nil, 0, true)
			slog.Debug("DNS lookup failed, cached negative (LookupHost)", "hostname", host, "error", err)
		} else {
			// For other errors, check if we can serve stale entry
			if entry, found := r.cache.Get(host); found && entry.IsStale() {
				addrs := make([]string, len(entry.IPs))
				for i, ip := range entry.IPs {
					addrs[i] = ip.String()
				}
				slog.Debug("DNS lookup failed, serving stale entry (LookupHost)", "hostname", host, "error", err)
				return addrs, nil
			}
		}
		return nil, err
	}

	// Convert addresses to IPs for caching
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil {
			ips = append(ips, ip)
		}
	}

	// Cache positive response
	ttl := 0 * time.Second // Will use default TTL
	r.cache.Put(host, ips, ttl, false)
	slog.Debug("DNS lookup successful, cached (LookupHost)", "hostname", host, "addrs", len(addrs))

	return addrs, nil
}

// LookupAddr performs a reverse lookup for the given address
func (r *Resolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	// Reverse lookups are typically not cached, use base resolver
	return r.base.LookupAddr(ctx, addr)
}

// LookupCNAME looks up the CNAME for the given hostname
func (r *Resolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	// CNAME lookups are typically not cached, use base resolver
	return r.base.LookupCNAME(ctx, host)
}

// LookupMX looks up MX records for the given hostname
func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	// MX lookups are typically not cached, use base resolver
	return r.base.LookupMX(ctx, name)
}

// LookupNS looks up NS records for the given hostname
func (r *Resolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	// NS lookups are typically not cached, use base resolver
	return r.base.LookupNS(ctx, name)
}

// LookupTXT looks up TXT records for the given hostname
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	// TXT lookups are typically not cached, use base resolver
	return r.base.LookupTXT(ctx, name)
}

// LookupSRV looks up SRV records for the given service, protocol, and name
func (r *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	// SRV lookups are typically not cached, use base resolver
	return r.base.LookupSRV(ctx, service, proto, name)
}

// LookupPort looks up the port for the given network and service
func (r *Resolver) LookupPort(ctx context.Context, network, service string) (int, error) {
	// Port lookups are typically not cached, use base resolver
	return r.base.LookupPort(ctx, network, service)
}

// GetCache returns the underlying cache (for testing and stats)
func (r *Resolver) GetCache() *Cache {
	return r.cache
}

