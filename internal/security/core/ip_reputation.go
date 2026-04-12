// Package security provides threat intelligence and security analysis for network traffic.
package security

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// IPReputationConfig configures IP reputation feed integration.
type IPReputationConfig struct {
	Enabled         bool             `json:"enabled,omitempty"`
	Feeds           []ReputationFeed `json:"feeds,omitempty"`
	RefreshInterval time.Duration    `json:"refresh_interval,omitempty"` // Default: 6h
	ScoreThreshold  float64          `json:"score_threshold,omitempty"`  // Block IPs above this score (0-100, default: 75)
	Action          string           `json:"action,omitempty"`           // "block", "challenge", "log" (default: "block")
	WhitelistCIDRs  []string         `json:"whitelist_cidrs,omitempty"`  // Always allow these
}

// ReputationFeed defines an external IP reputation data source.
type ReputationFeed struct {
	Name       string  `json:"name"`                  // e.g., "abuseipdb", "spamhaus-drop"
	URL        string  `json:"url"`                   // Feed URL
	Type       string  `json:"type"`                  // "ip_list", "cidr_list", "csv", "json"
	APIKey     string  `json:"api_key,omitempty"`     // API key if required
	ScoreField string  `json:"score_field,omitempty"` // JSON field for reputation score
	Weight     float64 `json:"weight,omitempty"`      // Weight for this feed (0-1, default: 1.0)
}

// FeedStats holds statistics for a single feed.
type FeedStats struct {
	EntriesLoaded int64     `json:"entries_loaded"`
	LastRefresh   time.Time `json:"last_refresh"`
	LastError     string    `json:"last_error,omitempty"`
}

// ReputationResult holds the result of an IP reputation check.
type ReputationResult struct {
	IP          string   `json:"ip"`
	Score       float64  `json:"score"`  // Combined reputation score (0-100)
	Action      string   `json:"action"` // "allow", "block", "challenge", "log"
	Feeds       []string `json:"feeds"`  // Which feeds flagged this IP
	Whitelisted bool     `json:"whitelisted"`
}

type feedStat struct {
	entriesLoaded atomic.Int64
	lastRefresh   time.Time
	lastError     string
}

type feedEntry struct {
	score float64
	feed  string
}

// IPReputationChecker checks IPs against reputation feeds.
type IPReputationChecker struct {
	config       IPReputationConfig
	client       *http.Client
	mu           sync.RWMutex
	blockedIPs   map[string][]feedEntry // IP -> entries from each feed
	blockedCIDRs []cidrEntry
	whitelist    []*net.IPNet
	lastRefresh  time.Time
	feedStats    map[string]*feedStat
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

type cidrEntry struct {
	network *net.IPNet
	score   float64
	feed    string
}

// NewIPReputationChecker creates a new reputation checker from the given config.
func NewIPReputationChecker(config IPReputationConfig) *IPReputationChecker {
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 6 * time.Hour
	}
	if config.ScoreThreshold <= 0 {
		config.ScoreThreshold = 75
	}
	if config.Action == "" {
		config.Action = "block"
	}

	// Normalize feed weights.
	for i := range config.Feeds {
		if config.Feeds[i].Weight <= 0 {
			config.Feeds[i].Weight = 1.0
		}
	}

	// Parse whitelist CIDRs.
	var whitelist []*net.IPNet
	for _, cidr := range config.WhitelistCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			whitelist = append(whitelist, ipNet)
		} else if ip := net.ParseIP(cidr); ip != nil {
			suffix := "/32"
			if strings.Contains(cidr, ":") {
				suffix = "/128"
			}
			if _, ipNet, err := net.ParseCIDR(cidr + suffix); err == nil {
				whitelist = append(whitelist, ipNet)
			}
		}
	}

	stats := make(map[string]*feedStat)
	for _, f := range config.Feeds {
		stats[f.Name] = &feedStat{}
	}

	return &IPReputationChecker{
		config:     config,
		client:     &http.Client{Timeout: 30 * time.Second},
		blockedIPs: make(map[string][]feedEntry),
		whitelist:  whitelist,
		feedStats:  stats,
		stopCh:     make(chan struct{}),
	}
}

// Start begins the background feed refresh loop.
func (c *IPReputationChecker) Start(ctx context.Context) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		// Initial load.
		if err := c.RefreshFeeds(ctx); err != nil {
			slog.Error("ip reputation initial refresh failed", "error", err)
		}

		ticker := time.NewTicker(c.config.RefreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-ticker.C:
				if err := c.RefreshFeeds(ctx); err != nil {
					slog.Error("ip reputation refresh failed", "error", err)
				}
			}
		}
	}()
}

// Stop halts the background loop.
func (c *IPReputationChecker) Stop() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	c.wg.Wait()
}

// Check evaluates an IP address against all loaded reputation feeds and returns
// the combined result.
func (c *IPReputationChecker) Check(ip string) *ReputationResult {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return &ReputationResult{IP: ip, Action: "allow"}
	}

	// Whitelist check first.
	if c.isWhitelisted(parsedIP) {
		return &ReputationResult{
			IP:          ip,
			Score:       0,
			Action:      "allow",
			Whitelisted: true,
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var totalScore float64
	var totalWeight float64
	var feeds []string

	// Check exact IP matches.
	if entries, ok := c.blockedIPs[ip]; ok {
		for _, e := range entries {
			totalScore += e.score
			totalWeight++
			feeds = append(feeds, e.feed)
		}
	}

	// Check CIDR matches.
	for _, entry := range c.blockedCIDRs {
		if entry.network.Contains(parsedIP) {
			totalScore += entry.score
			totalWeight++
			feeds = append(feeds, entry.feed)
		}
	}

	if totalWeight == 0 {
		return &ReputationResult{IP: ip, Score: 0, Action: "allow"}
	}

	combinedScore := totalScore / totalWeight
	action := "allow"
	if combinedScore >= c.config.ScoreThreshold {
		action = c.config.Action
	} else if combinedScore >= c.config.ScoreThreshold*0.7 {
		// Below threshold but suspicious - log it.
		action = "log"
	}

	return &ReputationResult{
		IP:     ip,
		Score:  combinedScore,
		Action: action,
		Feeds:  feeds,
	}
}

// RefreshFeeds fetches all configured feeds.
func (c *IPReputationChecker) RefreshFeeds(ctx context.Context) error {
	newIPs := make(map[string][]feedEntry)
	var newCIDRs []cidrEntry

	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error

	for _, feed := range c.config.Feeds {
		wg.Add(1)
		go func(f ReputationFeed) {
			defer wg.Done()
			ips, cidrs, err := c.loadFeed(ctx, f)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				if stat, ok := c.feedStats[f.Name]; ok {
					stat.lastError = err.Error()
				}
				slog.Warn("ip reputation feed load failed",
					"feed", f.Name,
					"error", err)
				return
			}
			for ip, entries := range ips {
				newIPs[ip] = append(newIPs[ip], entries...)
			}
			newCIDRs = append(newCIDRs, cidrs...)
			if stat, ok := c.feedStats[f.Name]; ok {
				stat.entriesLoaded.Store(int64(len(ips) + len(cidrs)))
				stat.lastRefresh = time.Now()
				stat.lastError = ""
			}
		}(feed)
	}
	wg.Wait()

	c.mu.Lock()
	c.blockedIPs = newIPs
	c.blockedCIDRs = newCIDRs
	c.lastRefresh = time.Now()
	c.mu.Unlock()

	return firstErr
}

// loadFeed fetches and parses a single feed.
func (c *IPReputationChecker) loadFeed(ctx context.Context, feed ReputationFeed) (map[string][]feedEntry, []cidrEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating request for %s: %w", feed.Name, err)
	}
	if feed.APIKey != "" {
		req.Header.Set("Key", feed.APIKey)
		req.Header.Set("Authorization", "Bearer "+feed.APIKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching feed %s: %w", feed.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("feed %s returned status %d", feed.Name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return nil, nil, fmt.Errorf("reading feed %s: %w", feed.Name, err)
	}

	switch feed.Type {
	case "ip_list":
		return c.parseIPList(body, feed)
	case "cidr_list":
		return c.parseCIDRList(body, feed)
	case "csv":
		return c.parseCSV(body, feed)
	case "json":
		return c.parseJSON(body, feed)
	default:
		return nil, nil, fmt.Errorf("unsupported feed type: %s", feed.Type)
	}
}

// parseIPList parses a plain-text list of IPs (one per line).
func (c *IPReputationChecker) parseIPList(data []byte, feed ReputationFeed) (map[string][]feedEntry, []cidrEntry, error) {
	ips := make(map[string][]feedEntry)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if net.ParseIP(line) != nil {
			ips[line] = append(ips[line], feedEntry{
				score: 100 * feed.Weight,
				feed:  feed.Name,
			})
		}
	}

	return ips, nil, nil
}

// parseCIDRList parses a plain-text list of CIDRs (one per line).
func (c *IPReputationChecker) parseCIDRList(data []byte, feed ReputationFeed) (map[string][]feedEntry, []cidrEntry, error) {
	var cidrs []cidrEntry
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Handle lines that may have trailing comments (e.g., Spamhaus DROP format).
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			cidrs = append(cidrs, cidrEntry{
				network: ipNet,
				score:   100 * feed.Weight,
				feed:    feed.Name,
			})
		}
	}

	return nil, cidrs, nil
}

// parseCSV parses a CSV feed. Expects at least one column containing IP addresses.
func (c *IPReputationChecker) parseCSV(data []byte, feed ReputationFeed) (map[string][]feedEntry, []cidrEntry, error) {
	ips := make(map[string][]feedEntry)
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.Comment = '#'
	reader.LazyQuotes = true

	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if len(record) == 0 {
			continue
		}
		// First column is IP.
		ip := strings.TrimSpace(record[0])
		if net.ParseIP(ip) == nil {
			continue
		}

		score := 100.0 * feed.Weight
		// If there is a second column, try to parse it as a score.
		if len(record) > 1 {
			var s float64
			if _, err := fmt.Sscanf(strings.TrimSpace(record[1]), "%f", &s); err == nil {
				score = s * feed.Weight
			}
		}

		ips[ip] = append(ips[ip], feedEntry{
			score: score,
			feed:  feed.Name,
		})
	}

	return ips, nil, nil
}

// parseJSON parses a JSON array of objects. Each object should have an "ip"
// field, and optionally a score field (configured via ScoreField).
func (c *IPReputationChecker) parseJSON(data []byte, feed ReputationFeed) (map[string][]feedEntry, []cidrEntry, error) {
	var items []map[string]interface{}
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, nil, fmt.Errorf("parsing JSON feed %s: %w", feed.Name, err)
	}

	ips := make(map[string][]feedEntry)
	scoreField := feed.ScoreField
	if scoreField == "" {
		scoreField = "score"
	}

	for _, item := range items {
		ipVal, ok := item["ip"]
		if !ok {
			continue
		}
		ipStr, ok := ipVal.(string)
		if !ok || net.ParseIP(ipStr) == nil {
			continue
		}

		score := 100.0 * feed.Weight
		if sv, ok := item[scoreField]; ok {
			switch v := sv.(type) {
			case float64:
				score = v * feed.Weight
			case int:
				score = float64(v) * feed.Weight
			}
		}

		ips[ipStr] = append(ips[ipStr], feedEntry{
			score: score,
			feed:  feed.Name,
		})
	}

	return ips, nil, nil
}

// isWhitelisted checks if the given IP is in the whitelist.
func (c *IPReputationChecker) isWhitelisted(ip net.IP) bool {
	for _, ipNet := range c.whitelist {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// Stats returns per-feed statistics.
func (c *IPReputationChecker) Stats() map[string]FeedStats {
	out := make(map[string]FeedStats)
	for name, stat := range c.feedStats {
		out[name] = FeedStats{
			EntriesLoaded: stat.entriesLoaded.Load(),
			LastRefresh:   stat.lastRefresh,
			LastError:     stat.lastError,
		}
	}
	return out
}
