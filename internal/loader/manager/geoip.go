// Package manager defines the Manager interface for coordinating proxy lifecycle and configuration reloads.
package manager

import (
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/request/geoip"
)

// GetLocation retrieves location information for the given request
func (m *managerImpl) GetLocation(req *http.Request) (*geoip.Result, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}

	// no geoip manager
	if m.geoip == nil {
		slog.Debug("geoip manager not initialized")
		return nil, nil
	}

	remoteAddr := req.RemoteAddr
	if remoteAddr == "" {
		return nil, errors.New("remote address not available")
	}

	slog.Debug("getting location", "remote_addr", remoteAddr)

	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		slog.Error("failed to split host and port", "remote_addr", remoteAddr, "error", err)
		return nil, err
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		slog.Error("invalid IP address", "ip", ipStr)
		return nil, errors.New("invalid IP address")
	}

	// Check if it's a private IP
	if isPrivateIP(ip) {
		slog.Debug("private IP address, returning nil location", "ip", ipStr)
		return nil, nil
	}

	result, err := m.geoip.Lookup(ip)
	if err != nil {
		slog.Error("failed to lookup location", "ip", ipStr, "error", err)
		return nil, err
	}

	slog.Info("location retrieved", "ip", ipStr, "country", result.Country)
	return result, nil
}

// isPrivateIP checks if the IP address is private
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
