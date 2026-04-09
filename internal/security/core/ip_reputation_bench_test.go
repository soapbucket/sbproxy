package security

import (
	"fmt"
	"testing"
)

func BenchmarkIPReputationChecker_Check_NotBlocked(b *testing.B) {
	b.ReportAllocs()
	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled:        true,
		ScoreThreshold: 75,
		Action:         "block",
	})
	// Pre-populate with blocked IPs to make the map non-trivial.
	checker.mu.Lock()
	for i := 0; i < 1000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		checker.blockedIPs[ip] = []feedEntry{{score: 85.0, feed: "test-feed"}}
	}
	checker.mu.Unlock()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check("192.168.1.1") // Not in blocklist
	}
}

func BenchmarkIPReputationChecker_Check_Blocked(b *testing.B) {
	b.ReportAllocs()
	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled:        true,
		ScoreThreshold: 75,
		Action:         "block",
	})
	checker.mu.Lock()
	checker.blockedIPs["10.0.0.1"] = []feedEntry{{score: 90.0, feed: "test-feed"}}
	checker.mu.Unlock()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check("10.0.0.1")
	}
}

func BenchmarkIPReputationChecker_Check_Whitelisted(b *testing.B) {
	b.ReportAllocs()
	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled:        true,
		ScoreThreshold: 75,
		Action:         "block",
		WhitelistCIDRs: []string{"192.168.0.0/16"},
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check("192.168.1.1")
	}
}

func BenchmarkIPReputationChecker_Check_InvalidIP(b *testing.B) {
	b.ReportAllocs()
	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled:        true,
		ScoreThreshold: 75,
		Action:         "block",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check("not-an-ip")
	}
}
