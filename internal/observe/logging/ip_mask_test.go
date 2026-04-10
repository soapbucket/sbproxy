package logging

import (
	"net"
	"testing"
)

func TestMaskIP_Truncate_IPv4(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.100", "192.168.1.0"},
		{"10.0.0.1", "10.0.0.0"},
		{"255.255.255.255", "255.255.255.0"},
	}
	for _, tt := range tests {
		got := maskIP(tt.input, "truncate")
		if got != tt.expected {
			t.Errorf("maskIP(%q, truncate) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMaskIP_Truncate_IPv6(t *testing.T) {
	result := maskIP("2001:db8::1", "truncate")
	if result == "2001:db8::1" {
		t.Error("IPv6 address should be truncated")
	}
	// Should zero last 80 bits
	parsed := net.ParseIP(result)
	if parsed == nil {
		t.Fatalf("result %q is not a valid IP", result)
	}
}

func TestMaskIP_Hash(t *testing.T) {
	result := maskIP("192.168.1.100", "hash")
	if len(result) != 16 {
		t.Errorf("hash should produce 16 hex chars, got %d: %s", len(result), result)
	}

	// Same IP should produce same hash (deterministic)
	result2 := maskIP("192.168.1.100", "hash")
	if result != result2 {
		t.Error("same IP should produce same hash")
	}

	// Different IP should produce different hash
	result3 := maskIP("10.0.0.1", "hash")
	if result == result3 {
		t.Error("different IPs should produce different hashes")
	}
}

func TestMaskIP_None(t *testing.T) {
	result := maskIP("192.168.1.100", "none")
	if result != "192.168.1.100" {
		t.Errorf("mode none should return original IP, got %s", result)
	}
}

func TestMaskIP_EmptyMode(t *testing.T) {
	result := maskIP("192.168.1.100", "")
	if result != "192.168.1.100" {
		t.Errorf("empty mode should return original IP, got %s", result)
	}
}

func TestMaskIP_InvalidIP(t *testing.T) {
	result := maskIP("not-an-ip", "truncate")
	if result != "not-an-ip" {
		t.Errorf("invalid IP should be returned as-is, got %s", result)
	}
}
