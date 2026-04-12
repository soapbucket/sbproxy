// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// AutoUpdateConfig configures automatic CRS rule updates.
type AutoUpdateConfig struct {
	Enabled         bool          `json:"enabled,omitempty"`
	Sources         []RuleSource  `json:"sources,omitempty"`          // External rule sources
	CheckInterval   time.Duration `json:"check_interval,omitempty"`   // Default: 24h
	MaxRules        int           `json:"max_rules,omitempty"`        // Max rules to load (default: 10000)
	VerifySignature bool          `json:"verify_signature,omitempty"` // Verify rule source signatures
	OnUpdateAction  string        `json:"on_update_action,omitempty"` // "reload" or "append" (default: "reload")
}

// RuleSource defines an external source for WAF rules.
type RuleSource struct {
	Name   string `json:"name"`             // e.g., "owasp-crs"
	URL    string `json:"url"`              // GitHub releases API or direct URL
	Type   string `json:"type"`             // "github_release", "http", "file"
	Format string `json:"format,omitempty"` // "json", "modsecurity" (default: "json")
	Token  string `json:"token,omitempty"`  // Auth token for private repos
}

// AutoUpdateStats holds statistics about auto-update operations.
type AutoUpdateStats struct {
	LastUpdate  time.Time `json:"last_update"`
	LastVersion string    `json:"last_version"`
	UpdateCount int64     `json:"update_count"`
	ErrorCount  int64     `json:"error_count"`
	RuleCount   int       `json:"rule_count"`
}

// AutoUpdater manages background WAF rule updates.
type AutoUpdater struct {
	config      AutoUpdateConfig
	client      *http.Client
	mu          sync.RWMutex
	rules       []WAFRule
	lastUpdate  time.Time
	lastVersion string
	lastETags   map[string]string // source URL -> ETag
	updateCount atomic.Int64
	errorCount  atomic.Int64
	stopCh      chan struct{}
	wg          sync.WaitGroup
	onUpdate    func([]WAFRule) // callback when rules are updated
}

// NewAutoUpdater creates a new AutoUpdater with the given config and callback.
func NewAutoUpdater(config AutoUpdateConfig, onUpdate func([]WAFRule)) *AutoUpdater {
	if config.CheckInterval <= 0 {
		config.CheckInterval = 24 * time.Hour
	}
	if config.MaxRules <= 0 {
		config.MaxRules = 10000
	}
	if config.OnUpdateAction == "" {
		config.OnUpdateAction = "reload"
	}

	return &AutoUpdater{
		config:    config,
		client:    &http.Client{Timeout: 30 * time.Second},
		lastETags: make(map[string]string),
		stopCh:    make(chan struct{}),
		onUpdate:  onUpdate,
	}
}

// Start begins the background check loop.
func (u *AutoUpdater) Start(ctx context.Context) {
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()

		// Perform an initial check immediately.
		if _, err := u.CheckForUpdates(ctx); err != nil {
			slog.Error("waf auto-update initial check failed", "error", err)
		}

		ticker := time.NewTicker(u.config.CheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-u.stopCh:
				return
			case <-ticker.C:
				if _, err := u.CheckForUpdates(ctx); err != nil {
					slog.Error("waf auto-update check failed", "error", err)
				}
			}
		}
	}()
}

// Stop halts the background loop and waits for goroutines to finish.
func (u *AutoUpdater) Stop() {
	select {
	case <-u.stopCh:
		// already closed
	default:
		close(u.stopCh)
	}
	u.wg.Wait()
}

// CheckForUpdates checks all configured sources for new rules. It returns true
// if rules were updated.
func (u *AutoUpdater) CheckForUpdates(ctx context.Context) (bool, error) {
	if len(u.config.Sources) == 0 {
		return false, nil
	}

	var allRules []WAFRule
	updated := false

	for _, src := range u.config.Sources {
		rules, version, err := u.fetchRulesFromSource(ctx, src)
		if err != nil {
			u.errorCount.Add(1)
			slog.Warn("waf auto-update source fetch failed",
				"source", src.Name,
				"error", err)
			continue
		}

		// Check if version changed (for github_release sources).
		if src.Type == "github_release" && version != "" {
			u.mu.RLock()
			prev := u.lastVersion
			u.mu.RUnlock()
			if version == prev {
				continue
			}
			// Version changed, even without rules this counts as an update.
			u.mu.Lock()
			u.lastVersion = version
			u.mu.Unlock()
			updated = true
		}

		if len(rules) == 0 {
			continue
		}

		allRules = append(allRules, rules...)
		if version != "" && src.Type != "github_release" {
			u.mu.Lock()
			u.lastVersion = version
			u.mu.Unlock()
		}
		updated = true
	}

	if !updated {
		return false, nil
	}

	// Enforce max rules limit.
	if len(allRules) > u.config.MaxRules {
		allRules = allRules[:u.config.MaxRules]
	}

	u.mu.Lock()
	if u.config.OnUpdateAction == "append" {
		u.rules = append(u.rules, allRules...)
		// Re-enforce max after append.
		if len(u.rules) > u.config.MaxRules {
			u.rules = u.rules[:u.config.MaxRules]
		}
	} else {
		u.rules = allRules
	}
	u.lastUpdate = time.Now()
	u.mu.Unlock()

	u.updateCount.Add(1)

	slog.Info("waf rules updated",
		"rule_count", len(allRules),
		"action", u.config.OnUpdateAction)

	if u.onUpdate != nil {
		u.mu.RLock()
		rulesCopy := make([]WAFRule, len(u.rules))
		copy(rulesCopy, u.rules)
		u.mu.RUnlock()
		u.onUpdate(rulesCopy)
	}

	return true, nil
}

// fetchRulesFromSource fetches and parses rules from a single source.
// Returns the parsed rules, a version string (if applicable), and any error.
func (u *AutoUpdater) fetchRulesFromSource(ctx context.Context, source RuleSource) ([]WAFRule, string, error) {
	switch source.Type {
	case "github_release":
		return u.fetchGitHubRelease(ctx, source)
	case "http":
		return u.fetchHTTP(ctx, source)
	default:
		return nil, "", fmt.Errorf("unsupported source type: %s", source.Type)
	}
}

// fetchGitHubRelease fetches rules from a GitHub releases API endpoint.
func (u *AutoUpdater) fetchGitHubRelease(ctx context.Context, source RuleSource) ([]WAFRule, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if source.Token != "" {
		req.Header.Set("Authorization", "Bearer "+source.Token)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetching github release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("github release returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("reading github release body: %w", err)
	}

	// Parse the release response to get tag_name and asset URLs.
	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		// Not a release response. Try parsing as direct rules JSON.
		rules, parseErr := u.parseJSONRules(body)
		if parseErr != nil {
			return nil, "", fmt.Errorf("parsing github response: %w", err)
		}
		return rules, "", nil
	}

	// If there is a tag but no assets, the body itself might contain rules.
	if len(release.Assets) == 0 {
		rules, parseErr := u.parseJSONRules(body)
		if parseErr != nil {
			return nil, release.TagName, nil
		}
		return rules, release.TagName, nil
	}

	// Download the first JSON asset.
	for _, asset := range release.Assets {
		if source.Format == "json" || source.Format == "" {
			assetReq, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.BrowserDownloadURL, nil)
			if err != nil {
				continue
			}
			if source.Token != "" {
				assetReq.Header.Set("Authorization", "Bearer "+source.Token)
			}
			assetResp, err := u.client.Do(assetReq)
			if err != nil {
				continue
			}
			assetBody, err := io.ReadAll(io.LimitReader(assetResp.Body, 10*1024*1024))
			assetResp.Body.Close()
			if err != nil {
				continue
			}
			rules, err := u.parseJSONRules(assetBody)
			if err != nil {
				continue
			}
			return rules, release.TagName, nil
		}
	}

	return nil, release.TagName, nil
}

// fetchHTTP fetches rules from a plain HTTP endpoint, using ETag for change detection.
func (u *AutoUpdater) fetchHTTP(ctx context.Context, source RuleSource) ([]WAFRule, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	if source.Token != "" {
		req.Header.Set("Authorization", "Bearer "+source.Token)
	}

	// Send If-None-Match if we have a previous ETag.
	u.mu.RLock()
	etag := u.lastETags[source.URL]
	u.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetching http source: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("http source returned status %d", resp.StatusCode)
	}

	// Store new ETag.
	if newETag := resp.Header.Get("ETag"); newETag != "" {
		u.mu.Lock()
		u.lastETags[source.URL] = newETag
		u.mu.Unlock()
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("reading http source body: %w", err)
	}

	rules, err := u.parseJSONRules(body)
	if err != nil {
		return nil, "", fmt.Errorf("parsing http source rules: %w", err)
	}

	return rules, "", nil
}

// parseJSONRules parses a JSON-formatted rule set. It accepts either a bare
// array of WAFRule objects or an object with a "rules" key.
func (u *AutoUpdater) parseJSONRules(data []byte) ([]WAFRule, error) {
	// Try array first.
	var rules []WAFRule
	if err := json.Unmarshal(data, &rules); err == nil && len(rules) > 0 {
		return rules, nil
	}

	// Try object with "rules" key.
	var wrapper struct {
		Rules []WAFRule `json:"rules"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid rule JSON: %w", err)
	}
	return wrapper.Rules, nil
}

// Rules returns the current set of loaded rules (thread-safe).
func (u *AutoUpdater) Rules() []WAFRule {
	u.mu.RLock()
	defer u.mu.RUnlock()
	out := make([]WAFRule, len(u.rules))
	copy(out, u.rules)
	return out
}

// Stats returns update statistics.
func (u *AutoUpdater) Stats() AutoUpdateStats {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return AutoUpdateStats{
		LastUpdate:  u.lastUpdate,
		LastVersion: u.lastVersion,
		UpdateCount: u.updateCount.Load(),
		ErrorCount:  u.errorCount.Load(),
		RuleCount:   len(u.rules),
	}
}
