package proxy

import (
	"net/http"
	"testing"
)

func TestTrustValidator_TrustAll(t *testing.T) {
	tv, err := NewTrustValidator(TrustAll, nil, 0)
	if err != nil {
		t.Fatalf("failed to create trust validator: %v", err)
	}

	// All IPs should be trusted
	testIPs := []string{"10.0.0.1", "192.168.1.1", "8.8.8.8"}
	for _, ip := range testIPs {
		if !tv.IsTrusted(ip) {
			t.Errorf("expected %s to be trusted in TrustAll mode", ip)
		}
	}
}

func TestTrustValidator_TrustNone(t *testing.T) {
	tv, err := NewTrustValidator(TrustNone, nil, 0)
	if err != nil {
		t.Fatalf("failed to create trust validator: %v", err)
	}

	// No IPs should be trusted
	testIPs := []string{"10.0.0.1", "192.168.1.1", "8.8.8.8"}
	for _, ip := range testIPs {
		if tv.IsTrusted(ip) {
			t.Errorf("expected %s to be untrusted in TrustNone mode", ip)
		}
	}
}

func TestTrustValidator_TrustTrustedProxies(t *testing.T) {
	tv, err := NewTrustValidator(TrustTrustedProxies, []string{"10.0.0.0/8", "192.168.0.0/16"}, 0)
	if err != nil {
		t.Fatalf("failed to create trust validator: %v", err)
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},    // In 10.0.0.0/8
		{"10.255.255.255", true}, // In 10.0.0.0/8
		{"192.168.1.1", true}, // In 192.168.0.0/16
		{"172.16.0.1", false}, // Not in trusted CIDRs
		{"8.8.8.8", false},    // Public IP
	}

	for _, tt := range tests {
		result := tv.IsTrusted(tt.ip)
		if result != tt.expected {
			t.Errorf("IP %s: expected trusted=%v, got %v", tt.ip, tt.expected, result)
		}
	}
}

func TestTrustValidator_ExtractClientIP(t *testing.T) {
	tv, err := NewTrustValidator(TrustTrustedProxies, []string{"10.0.0.0/8"}, 0)
	if err != nil {
		t.Fatalf("failed to create trust validator: %v", err)
	}

	tests := []struct {
		name     string
		xff      string
		expected string
	}{
		{
			name:     "No XFF",
			xff:      "",
			expected: "192.168.1.100", // From RemoteAddr
		},
		{
			name:     "Single IP",
			xff:      "203.0.113.1",
			expected: "203.0.113.1",
		},
		{
			name:     "Chain with trusted proxy",
			xff:      "203.0.113.1, 10.0.0.1",
			expected: "203.0.113.1", // First untrusted
		},
		{
			name:     "Chain with multiple untrusted",
			xff:      "203.0.113.1, 198.51.100.1, 10.0.0.1",
			expected: "198.51.100.1", // Last untrusted in chain
		},
		{
			name:     "All trusted",
			xff:      "10.0.0.1, 10.0.0.2",
			expected: "10.0.0.1", // Return first (original client)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: "192.168.1.100:12345",
				Header:     http.Header{},
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			clientIP := tv.ExtractClientIP(req)
			if clientIP != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, clientIP)
			}
		})
	}
}

func TestTrustValidator_InvalidCIDR(t *testing.T) {
	_, err := NewTrustValidator(TrustTrustedProxies, []string{"invalid-cidr"}, 0)
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

