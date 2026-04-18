// Package policy imports all built-in policy modules so they register
// themselves into the pkg/plugin registry via their init() functions.
package policy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// SSRFConfig configures SSRF protection.
type SSRFConfig struct {
	Enabled         bool     `json:"enabled" yaml:"enabled"`
	BlockPrivateIPs bool     `json:"block_private_ips,omitempty" yaml:"block_private_ips"`
	AllowedHosts    []string `json:"allowed_hosts,omitempty" yaml:"allowed_hosts"`
	BlockedPorts    []int    `json:"blocked_ports,omitempty" yaml:"blocked_ports"`
}

// ValidateURL checks if a URL is safe from SSRF attacks.
// It validates the scheme, resolves the hostname to IP addresses, and checks
// each resolved IP against private ranges and the allowed hosts list.
func ValidateURL(rawURL string, cfg SSRFConfig) error {
	if !cfg.Enabled {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("ssrf: invalid URL: %w", err)
	}

	// Only allow http and https schemes.
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("ssrf: scheme %q is not allowed", parsed.Scheme)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("ssrf: empty hostname")
	}

	// Check allowed hosts if configured.
	if len(cfg.AllowedHosts) > 0 {
		allowed := false
		for _, h := range cfg.AllowedHosts {
			if strings.EqualFold(hostname, h) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("ssrf: host %q is not in the allowed hosts list", hostname)
		}
	}

	// Check blocked ports.
	if len(cfg.BlockedPorts) > 0 {
		portStr := parsed.Port()
		if portStr == "" {
			// Default ports for http/https.
			if scheme == "http" {
				portStr = "80"
			} else {
				portStr = "443"
			}
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("ssrf: invalid port %q: %w", portStr, err)
		}
		for _, bp := range cfg.BlockedPorts {
			if port == bp {
				return fmt.Errorf("ssrf: port %d is blocked", port)
			}
		}
	}

	// Check for private/reserved IPs.
	if cfg.BlockPrivateIPs {
		// First check if the hostname is already an IP address.
		if ip := net.ParseIP(hostname); ip != nil {
			if IsPrivateIP(ip) {
				return fmt.Errorf("ssrf: IP address %s is in a private/reserved range", ip)
			}
			return nil
		}

		// Resolve hostname to IP addresses.
		ips, err := net.LookupIP(hostname)
		if err != nil {
			return fmt.Errorf("ssrf: failed to resolve hostname %q: %w", hostname, err)
		}

		for _, ip := range ips {
			if IsPrivateIP(ip) {
				return fmt.Errorf("ssrf: hostname %q resolves to private IP %s", hostname, ip)
			}
		}
	}

	return nil
}

// IsPrivateIP checks if an IP address is in a private or reserved range.
// This includes RFC 1918 private addresses, loopback, link-local, and other
// reserved ranges that should not be reachable from a public proxy.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check common private/reserved ranges.
	privateRanges := []struct {
		network string
		mask    string
	}{
		{"10.0.0.0", "255.0.0.0"},           // RFC 1918 Class A
		{"172.16.0.0", "255.240.0.0"},        // RFC 1918 Class B
		{"192.168.0.0", "255.255.0.0"},       // RFC 1918 Class C
		{"127.0.0.0", "255.0.0.0"},           // Loopback
		{"169.254.0.0", "255.255.0.0"},       // Link-local
		{"0.0.0.0", "255.0.0.0"},             // Current network
		{"100.64.0.0", "255.192.0.0"},        // Shared address space (CGN)
		{"192.0.0.0", "255.255.255.0"},       // IETF protocol assignments
		{"192.0.2.0", "255.255.255.0"},       // TEST-NET-1
		{"198.51.100.0", "255.255.255.0"},    // TEST-NET-2
		{"203.0.113.0", "255.255.255.0"},     // TEST-NET-3
		{"198.18.0.0", "255.254.0.0"},        // Benchmarking
		{"240.0.0.0", "240.0.0.0"},           // Reserved (Class E)
	}

	// Normalize to IPv4 if possible.
	ip4 := ip.To4()

	for _, pr := range privateRanges {
		network := net.ParseIP(pr.network)
		mask := net.IPMask(net.ParseIP(pr.mask).To4())
		if ip4 != nil && network != nil && mask != nil {
			cidr := &net.IPNet{
				IP:   network.To4(),
				Mask: mask,
			}
			if cidr.Contains(ip4) {
				return true
			}
		}
	}

	// IPv6 private/reserved ranges.
	if ip4 == nil {
		// Loopback (::1)
		if ip.Equal(net.IPv6loopback) {
			return true
		}
		// Link-local unicast (fe80::/10)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return true
		}
		// Unique local address (fc00::/7)
		if (ip[0] & 0xfe) == 0xfc {
			return true
		}
		// IPv4-mapped IPv6 (::ffff:0:0/96) - check the embedded IPv4.
		if ip4mapped := ip.To4(); ip4mapped != nil {
			return IsPrivateIP(ip4mapped)
		}
	}

	return false
}
