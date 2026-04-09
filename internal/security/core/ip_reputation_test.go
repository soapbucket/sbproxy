package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIPReputationChecker_Check(t *testing.T) {
	t.Parallel()

	ipList := "# Blocklist\n10.0.0.1\n10.0.0.2\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ipList))
	}))
	defer srv.Close()

	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled:        true,
		ScoreThreshold: 75,
		Action:         "block",
		Feeds: []ReputationFeed{
			{
				Name:   "test-feed",
				URL:    srv.URL,
				Type:   "ip_list",
				Weight: 1.0,
			},
		},
	})

	err := checker.RefreshFeeds(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Blocked IP should be detected.
	result := checker.Check("10.0.0.1")
	if result.Action != "block" {
		t.Errorf("expected action block for 10.0.0.1, got %s (score: %.1f)", result.Action, result.Score)
	}
	if result.Score == 0 {
		t.Error("expected non-zero score for blocked IP")
	}
	if len(result.Feeds) == 0 {
		t.Error("expected at least one feed to flag this IP")
	}

	// Clean IP should pass.
	result = checker.Check("192.168.1.1")
	if result.Action != "allow" {
		t.Errorf("expected action allow for clean IP, got %s", result.Action)
	}
}

func TestIPReputationChecker_Whitelist(t *testing.T) {
	t.Parallel()

	ipList := "10.0.0.5\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ipList))
	}))
	defer srv.Close()

	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled:        true,
		ScoreThreshold: 75,
		Action:         "block",
		WhitelistCIDRs: []string{"10.0.0.0/24"},
		Feeds: []ReputationFeed{
			{
				Name:   "test-feed",
				URL:    srv.URL,
				Type:   "ip_list",
				Weight: 1.0,
			},
		},
	})

	err := checker.RefreshFeeds(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Even though 10.0.0.5 is in the blocklist, it should be whitelisted.
	result := checker.Check("10.0.0.5")
	if !result.Whitelisted {
		t.Error("expected IP to be whitelisted")
	}
	if result.Action != "allow" {
		t.Errorf("expected action allow for whitelisted IP, got %s", result.Action)
	}
}

func TestIPReputationChecker_LoadIPListFeed(t *testing.T) {
	t.Parallel()

	ipList := strings.Join([]string{
		"# Comment line",
		"",
		"192.168.1.100",
		"; Another comment",
		"192.168.1.101",
		"invalid-not-ip",
		"192.168.1.102",
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ipList))
	}))
	defer srv.Close()

	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled:        true,
		ScoreThreshold: 75,
		Action:         "block",
		Feeds: []ReputationFeed{
			{
				Name:   "ip-list-feed",
				URL:    srv.URL,
				Type:   "ip_list",
				Weight: 1.0,
			},
		},
	})

	err := checker.RefreshFeeds(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have loaded 3 valid IPs.
	checker.mu.RLock()
	count := len(checker.blockedIPs)
	checker.mu.RUnlock()

	if count != 3 {
		t.Errorf("expected 3 IPs loaded, got %d", count)
	}

	stats := checker.Stats()
	feedStats, ok := stats["ip-list-feed"]
	if !ok {
		t.Fatal("expected stats for ip-list-feed")
	}
	if feedStats.EntriesLoaded != 3 {
		t.Errorf("expected 3 entries loaded, got %d", feedStats.EntriesLoaded)
	}
}

func TestIPReputationChecker_LoadCIDRFeed(t *testing.T) {
	t.Parallel()

	cidrList := strings.Join([]string{
		"# Spamhaus DROP",
		"10.0.0.0/8 ; SBL1234",
		"172.16.0.0/12",
		"invalid/cidr",
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(cidrList))
	}))
	defer srv.Close()

	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled:        true,
		ScoreThreshold: 75,
		Action:         "block",
		Feeds: []ReputationFeed{
			{
				Name:   "cidr-feed",
				URL:    srv.URL,
				Type:   "cidr_list",
				Weight: 1.0,
			},
		},
	})

	err := checker.RefreshFeeds(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have loaded 2 valid CIDRs.
	checker.mu.RLock()
	count := len(checker.blockedCIDRs)
	checker.mu.RUnlock()

	if count != 2 {
		t.Errorf("expected 2 CIDRs loaded, got %d", count)
	}

	// An IP within the CIDR should be blocked.
	result := checker.Check("10.1.2.3")
	if result.Action != "block" {
		t.Errorf("expected block for IP in CIDR, got %s", result.Action)
	}

	// An IP outside should be allowed.
	result = checker.Check("192.168.1.1")
	if result.Action != "allow" {
		t.Errorf("expected allow for IP outside CIDRs, got %s", result.Action)
	}
}

func TestIPReputationChecker_CombinedScore(t *testing.T) {
	t.Parallel()

	// Feed 1 returns IP with score 80.
	feed1Data, _ := json.Marshal([]map[string]interface{}{
		{"ip": "10.0.0.50", "score": 80.0},
	})

	// Feed 2 returns same IP with score 60.
	feed2Data, _ := json.Marshal([]map[string]interface{}{
		{"ip": "10.0.0.50", "score": 60.0},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/feed1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(feed1Data)
	})
	mux.HandleFunc("/feed2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(feed2Data)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled:        true,
		ScoreThreshold: 75,
		Action:         "block",
		Feeds: []ReputationFeed{
			{
				Name:       "feed1",
				URL:        fmt.Sprintf("%s/feed1", srv.URL),
				Type:       "json",
				ScoreField: "score",
				Weight:     1.0,
			},
			{
				Name:       "feed2",
				URL:        fmt.Sprintf("%s/feed2", srv.URL),
				Type:       "json",
				ScoreField: "score",
				Weight:     1.0,
			},
		},
	})

	err := checker.RefreshFeeds(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := checker.Check("10.0.0.50")

	// Combined score should be average of 80 and 60 = 70.
	// With threshold 75, this should not trigger a block but should trigger a log.
	expectedScore := 70.0
	if result.Score != expectedScore {
		t.Errorf("expected combined score %.1f, got %.1f", expectedScore, result.Score)
	}

	if len(result.Feeds) != 2 {
		t.Errorf("expected 2 feeds, got %d", len(result.Feeds))
	}

	// Score 70 is below threshold 75 but above 75*0.7=52.5, so action should be "log".
	if result.Action != "log" {
		t.Errorf("expected action log for score below threshold, got %s", result.Action)
	}
}

func TestIPReputationChecker_InvalidIP(t *testing.T) {
	t.Parallel()

	checker := NewIPReputationChecker(IPReputationConfig{
		Enabled: true,
	})

	result := checker.Check("not-an-ip")
	if result.Action != "allow" {
		t.Errorf("expected allow for invalid IP, got %s", result.Action)
	}
}
