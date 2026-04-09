package policy

import (
	"context"
	"testing"
	"time"
)

func TestNetworkEnforcer_CheckIP_Allowlist(t *testing.T) {
	tests := []struct {
		name        string
		allowedIPs  []string
		ip          string
		wantAllowed bool
	}{
		{
			name:        "IP in CIDR range",
			allowedIPs:  []string{"10.0.0.0/24"},
			ip:          "10.0.0.5",
			wantAllowed: true,
		},
		{
			name:        "IP not in CIDR range",
			allowedIPs:  []string{"10.0.0.0/24"},
			ip:          "10.0.1.5",
			wantAllowed: false,
		},
		{
			name:        "exact IP match",
			allowedIPs:  []string{"192.168.1.100"},
			ip:          "192.168.1.100",
			wantAllowed: true,
		},
		{
			name:        "multiple CIDRs, second matches",
			allowedIPs:  []string{"10.0.0.0/24", "172.16.0.0/16"},
			ip:          "172.16.5.10",
			wantAllowed: true,
		},
		{
			name:        "empty allowlist allows all",
			allowedIPs:  nil,
			ip:          "8.8.8.8",
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ne := NewNetworkEnforcer()
			err := ne.AddPolicy(&NetworkPolicy{
				ID:         "test-policy",
				AllowedIPs: tt.allowedIPs,
			})
			if err != nil {
				t.Fatalf("AddPolicy error: %v", err)
			}

			allowed, reason := ne.CheckIP(context.Background(), "test-policy", tt.ip)
			if allowed != tt.wantAllowed {
				t.Errorf("CheckIP(%q) = %v (%s), want %v", tt.ip, allowed, reason, tt.wantAllowed)
			}
		})
	}
}

func TestNetworkEnforcer_CheckIP_Blocklist(t *testing.T) {
	tests := []struct {
		name        string
		blockedIPs  []string
		ip          string
		wantAllowed bool
	}{
		{
			name:        "IP in blocked CIDR",
			blockedIPs:  []string{"192.168.0.0/16"},
			ip:          "192.168.1.1",
			wantAllowed: false,
		},
		{
			name:        "IP not in blocked CIDR",
			blockedIPs:  []string{"192.168.0.0/16"},
			ip:          "10.0.0.1",
			wantAllowed: true,
		},
		{
			name:        "exact blocked IP",
			blockedIPs:  []string{"1.2.3.4"},
			ip:          "1.2.3.4",
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ne := NewNetworkEnforcer()
			err := ne.AddPolicy(&NetworkPolicy{
				ID:         "block-policy",
				BlockedIPs: tt.blockedIPs,
			})
			if err != nil {
				t.Fatalf("AddPolicy error: %v", err)
			}

			allowed, _ := ne.CheckIP(context.Background(), "block-policy", tt.ip)
			if allowed != tt.wantAllowed {
				t.Errorf("CheckIP(%q) = %v, want %v", tt.ip, allowed, tt.wantAllowed)
			}
		})
	}
}

func TestNetworkEnforcer_CheckIP_BlockTakesPrecedence(t *testing.T) {
	ne := NewNetworkEnforcer()
	err := ne.AddPolicy(&NetworkPolicy{
		ID:         "mixed",
		AllowedIPs: []string{"10.0.0.0/8"},
		BlockedIPs: []string{"10.0.0.5/32"},
	})
	if err != nil {
		t.Fatalf("AddPolicy error: %v", err)
	}

	// 10.0.0.5 is in both allowed and blocked. Blocked should win.
	allowed, _ := ne.CheckIP(context.Background(), "mixed", "10.0.0.5")
	if allowed {
		t.Error("expected 10.0.0.5 to be blocked (block takes precedence over allow)")
	}

	// 10.0.0.6 is in allowed but not blocked.
	allowed, _ = ne.CheckIP(context.Background(), "mixed", "10.0.0.6")
	if !allowed {
		t.Error("expected 10.0.0.6 to be allowed")
	}
}

func TestNetworkEnforcer_CheckIP_IPv6(t *testing.T) {
	tests := []struct {
		name        string
		allowedIPs  []string
		blockedIPs  []string
		ip          string
		wantAllowed bool
	}{
		{
			name:        "IPv6 in allowed CIDR",
			allowedIPs:  []string{"2001:db8::/32"},
			ip:          "2001:db8::1",
			wantAllowed: true,
		},
		{
			name:        "IPv6 not in allowed CIDR",
			allowedIPs:  []string{"2001:db8::/32"},
			ip:          "2001:db9::1",
			wantAllowed: false,
		},
		{
			name:        "IPv6 blocked",
			blockedIPs:  []string{"::1/128"},
			ip:          "::1",
			wantAllowed: false,
		},
		{
			name:        "IPv6 exact match allowed",
			allowedIPs:  []string{"fe80::1"},
			ip:          "fe80::1",
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ne := NewNetworkEnforcer()
			err := ne.AddPolicy(&NetworkPolicy{
				ID:         "ipv6-policy",
				AllowedIPs: tt.allowedIPs,
				BlockedIPs: tt.blockedIPs,
			})
			if err != nil {
				t.Fatalf("AddPolicy error: %v", err)
			}

			allowed, _ := ne.CheckIP(context.Background(), "ipv6-policy", tt.ip)
			if allowed != tt.wantAllowed {
				t.Errorf("CheckIP(%q) = %v, want %v", tt.ip, allowed, tt.wantAllowed)
			}
		})
	}
}

func TestNetworkEnforcer_CheckIP_InvalidIP(t *testing.T) {
	ne := NewNetworkEnforcer()
	err := ne.AddPolicy(&NetworkPolicy{ID: "test"})
	if err != nil {
		t.Fatalf("AddPolicy error: %v", err)
	}

	allowed, reason := ne.CheckIP(context.Background(), "test", "not-an-ip")
	if allowed {
		t.Error("expected invalid IP to be rejected")
	}
	if reason == "" {
		t.Error("expected a reason for rejection")
	}
}

func TestNetworkEnforcer_CheckIP_NoPolicyAllows(t *testing.T) {
	ne := NewNetworkEnforcer()

	// No policy registered, should allow by default.
	allowed, _ := ne.CheckIP(context.Background(), "nonexistent", "1.2.3.4")
	if !allowed {
		t.Error("expected allow when no policy exists")
	}
}

func TestNetworkEnforcer_AddPolicy_InvalidCIDR(t *testing.T) {
	ne := NewNetworkEnforcer()

	err := ne.AddPolicy(&NetworkPolicy{
		ID:         "bad",
		AllowedIPs: []string{"not-a-cidr"},
	})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}

	err = ne.AddPolicy(&NetworkPolicy{
		ID:         "bad2",
		BlockedIPs: []string{"also-not-cidr"},
	})
	if err == nil {
		t.Error("expected error for invalid blocked CIDR")
	}
}

func TestNetworkEnforcer_AuthFailureRateLimiting(t *testing.T) {
	ne := NewNetworkEnforcer()
	err := ne.AddPolicy(&NetworkPolicy{
		ID:                "rate-limit",
		AuthFailureLimit:  3,
		AuthFailureWindow: 1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("AddPolicy error: %v", err)
	}

	ip := "10.0.0.1"

	// Should not be rate limited initially.
	if ne.IsRateLimited(ip) {
		t.Error("expected not rate limited initially")
	}

	// Record failures below the limit.
	ne.RecordAuthFailure(ip)
	ne.RecordAuthFailure(ip)
	if ne.IsRateLimited(ip) {
		t.Error("expected not rate limited with 2 failures (limit is 3)")
	}

	// Third failure should trigger rate limiting.
	ne.RecordAuthFailure(ip)
	if !ne.IsRateLimited(ip) {
		t.Error("expected rate limited after 3 failures")
	}
}

func TestNetworkEnforcer_AuthFailure_DifferentIPs(t *testing.T) {
	ne := NewNetworkEnforcer()
	err := ne.AddPolicy(&NetworkPolicy{
		ID:                "rate-limit",
		AuthFailureLimit:  2,
		AuthFailureWindow: 1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("AddPolicy error: %v", err)
	}

	// Failures on different IPs should be independent.
	ne.RecordAuthFailure("10.0.0.1")
	ne.RecordAuthFailure("10.0.0.1")
	ne.RecordAuthFailure("10.0.0.2")

	if !ne.IsRateLimited("10.0.0.1") {
		t.Error("expected 10.0.0.1 to be rate limited")
	}
	if ne.IsRateLimited("10.0.0.2") {
		t.Error("expected 10.0.0.2 to NOT be rate limited (only 1 failure)")
	}
}

func TestNetworkEnforcer_AuthFailure_NoPolicyNoLimit(t *testing.T) {
	ne := NewNetworkEnforcer()

	// No policy with auth failure limits.
	err := ne.AddPolicy(&NetworkPolicy{ID: "no-limit"})
	if err != nil {
		t.Fatalf("AddPolicy error: %v", err)
	}

	ne.RecordAuthFailure("10.0.0.1")
	ne.RecordAuthFailure("10.0.0.1")
	ne.RecordAuthFailure("10.0.0.1")

	if ne.IsRateLimited("10.0.0.1") {
		t.Error("expected no rate limiting when policy has no auth failure limit")
	}
}

func TestNetworkEnforcer_AuthFailure_IPv6(t *testing.T) {
	ne := NewNetworkEnforcer()
	err := ne.AddPolicy(&NetworkPolicy{
		ID:                "rate-limit-v6",
		AuthFailureLimit:  2,
		AuthFailureWindow: 1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("AddPolicy error: %v", err)
	}

	ip := "2001:db8::1"
	ne.RecordAuthFailure(ip)
	ne.RecordAuthFailure(ip)

	if !ne.IsRateLimited(ip) {
		t.Error("expected IPv6 address to be rate limited after 2 failures")
	}
}
