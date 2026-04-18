package policy

import (
	"net"
	"testing"
)

func TestValidateURL_Disabled(t *testing.T) {
	err := ValidateURL("http://internal.local", SSRFConfig{Enabled: false})
	if err != nil {
		t.Fatalf("expected no error when disabled: %v", err)
	}
}

func TestValidateURL_InvalidScheme(t *testing.T) {
	err := ValidateURL("ftp://example.com", SSRFConfig{Enabled: true})
	if err == nil {
		t.Fatal("expected error for ftp scheme")
	}
}

func TestValidateURL_EmptyHostname(t *testing.T) {
	err := ValidateURL("http://", SSRFConfig{Enabled: true})
	if err == nil {
		t.Fatal("expected error for empty hostname")
	}
}

func TestValidateURL_AllowedHosts_Allowed(t *testing.T) {
	cfg := SSRFConfig{
		Enabled:      true,
		AllowedHosts: []string{"api.example.com"},
	}
	err := ValidateURL("https://api.example.com/path", cfg)
	if err != nil {
		t.Fatalf("expected host to be allowed: %v", err)
	}
}

func TestValidateURL_AllowedHosts_Blocked(t *testing.T) {
	cfg := SSRFConfig{
		Enabled:      true,
		AllowedHosts: []string{"api.example.com"},
	}
	err := ValidateURL("https://evil.example.com/path", cfg)
	if err == nil {
		t.Fatal("expected host to be blocked")
	}
}

func TestValidateURL_BlockedPorts(t *testing.T) {
	cfg := SSRFConfig{
		Enabled:      true,
		BlockedPorts: []int{6379, 3306},
	}
	err := ValidateURL("http://example.com:6379/", cfg)
	if err == nil {
		t.Fatal("expected port 6379 to be blocked")
	}
}

func TestValidateURL_BlockedPorts_DefaultPort(t *testing.T) {
	cfg := SSRFConfig{
		Enabled:      true,
		BlockedPorts: []int{80},
	}
	err := ValidateURL("http://example.com/path", cfg)
	if err == nil {
		t.Fatal("expected default port 80 to be blocked")
	}
}

func TestValidateURL_BlockedPorts_Allowed(t *testing.T) {
	cfg := SSRFConfig{
		Enabled:      true,
		BlockedPorts: []int{6379},
	}
	err := ValidateURL("https://example.com/path", cfg)
	if err != nil {
		t.Fatalf("expected port 443 to be allowed: %v", err)
	}
}

func TestValidateURL_PrivateIP_Direct(t *testing.T) {
	cfg := SSRFConfig{
		Enabled:         true,
		BlockPrivateIPs: true,
	}
	err := ValidateURL("http://127.0.0.1/path", cfg)
	if err == nil {
		t.Fatal("expected loopback IP to be blocked")
	}
}

func TestValidateURL_PrivateIP_192168(t *testing.T) {
	cfg := SSRFConfig{
		Enabled:         true,
		BlockPrivateIPs: true,
	}
	err := ValidateURL("http://192.168.1.1/path", cfg)
	if err == nil {
		t.Fatal("expected private IP to be blocked")
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"169.254.1.1", true},
		{"0.0.0.1", true},
		{"100.64.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"fd00::1", true},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := IsPrivateIP(ip)
			if got != tt.private {
				t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}

func TestIsPrivateIP_Nil(t *testing.T) {
	if IsPrivateIP(nil) {
		t.Error("expected false for nil IP")
	}
}

func TestValidateURL_InvalidURL(t *testing.T) {
	cfg := SSRFConfig{Enabled: true}
	err := ValidateURL("://bad", cfg)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestValidateURL_PublicIP(t *testing.T) {
	cfg := SSRFConfig{
		Enabled:         true,
		BlockPrivateIPs: true,
	}
	// This URL resolves to a public IP, but since DNS resolution may fail in CI,
	// we test with a direct IP that is public.
	err := ValidateURL("http://8.8.8.8/path", cfg)
	if err != nil {
		t.Fatalf("expected public IP to be allowed: %v", err)
	}
}
