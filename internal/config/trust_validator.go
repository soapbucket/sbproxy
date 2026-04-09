// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// TrustValidator validates proxy headers based on trust configuration
type TrustValidator struct {
	trustMode      TrustMode
	trustedCIDRs   []*net.IPNet
	trustedHops    int
}

// NewTrustValidator creates a new trust validator
func NewTrustValidator(trustMode TrustMode, trustedProxies []string, trustedHops int) (*TrustValidator, error) {
	tv := &TrustValidator{
		trustMode:   trustMode,
		trustedHops: trustedHops,
	}

	// Parse trusted proxy CIDRs
	if len(trustedProxies) > 0 {
		tv.trustedCIDRs = make([]*net.IPNet, 0, len(trustedProxies))
		for _, cidr := range trustedProxies {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
			}
			tv.trustedCIDRs = append(tv.trustedCIDRs, ipNet)
		}
	}

	return tv, nil
}

// IsTrusted checks if an IP is trusted based on the trust configuration
func (tv *TrustValidator) IsTrusted(ip string) bool {
	switch tv.trustMode {
	case TrustAll:
		return true
	case TrustNone:
		return false
	case TrustTrustedProxies:
		return tv.isIPInTrustedCIDRs(ip)
	default:
		return true
	}
}

// isIPInTrustedCIDRs checks if an IP is in any of the trusted CIDRs
func (tv *TrustValidator) isIPInTrustedCIDRs(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range tv.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// ExtractClientIP extracts the real client IP considering trust settings
// Returns the first untrusted IP in the X-Forwarded-For chain
func (tv *TrustValidator) ExtractClientIP(r *http.Request) string {
	// Get X-Forwarded-For chain
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		// No X-Forwarded-For, use RemoteAddr
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		return ip
	}

	// Parse X-Forwarded-For chain
	ips := parseXFFChain(xff)
	if len(ips) == 0 {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		return ip
	}

	// Find first untrusted IP (working backwards from most recent)
	for i := len(ips) - 1; i >= 0; i-- {
		ip := ips[i]
		if !tv.IsTrusted(ip) {
			return ip
		}
	}

	// All IPs are trusted, return the first (original client)
	return ips[0]
}

// TrimXFFChain trims the X-Forwarded-For chain to trusted hops
// Returns the trimmed chain
func (tv *TrustValidator) TrimXFFChain(xff string) string {
	if tv.trustedHops == 0 {
		return xff
	}

	ips := parseXFFChain(xff)
	if len(ips) <= tv.trustedHops {
		return xff
	}

	// Keep only the first (original client) and last N trusted hops
	kept := append([]string{ips[0]}, ips[len(ips)-tv.trustedHops:]...)
	return joinXFFChain(kept)
}

// parseXFFChain parses X-Forwarded-For header into IP list
func parseXFFChain(xff string) []string {
	parts := strings.Split(xff, ",")
	ips := make([]string, 0, len(parts))
	for _, part := range parts {
		ip := strings.TrimSpace(part)
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

// joinXFFChain joins IPs into X-Forwarded-For format
func joinXFFChain(ips []string) string {
	return strings.Join(ips, ", ")
}

