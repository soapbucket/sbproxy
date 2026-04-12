// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// BotDetectionConfig configures the bot detection middleware.
type BotDetectionConfig struct {
	Enabled       bool     `json:"enabled"`
	Mode          string   `json:"mode"`            // "block", "challenge", "log"
	AllowList     []string `json:"allow_list"`      // Known good bots (e.g., "googlebot", "bingbot")
	DenyList      []string `json:"deny_list"`       // Known bad bot patterns (matched case-insensitively against User-Agent)
	ChallengeType string   `json:"challenge_type"`  // "js" (default) or "captcha"
	VerifyGoodBot bool     `json:"verify_good_bot"` // Verify good bots via reverse DNS
}

// botDetectionState holds shared state for the bot detection middleware.
type botDetectionState struct {
	config         BotDetectionConfig
	denyPatterns   []string            // lowercased deny patterns
	allowPatterns  []string            // lowercased allow patterns
	goodBotDomains map[string][]string // user-agent substring -> expected DNS suffixes
	dnsCache       sync.Map            // IP -> *dnsCacheEntry
	dnsCacheTTL    time.Duration
}

// dnsCacheEntry caches reverse DNS lookup results.
type dnsCacheEntry struct {
	hostnames []string
	expiresAt time.Time
}

// Known good bot user-agent substrings and their expected reverse DNS domains.
var defaultGoodBotDomains = map[string][]string{
	"googlebot":   {".googlebot.com.", ".google.com."},
	"bingbot":     {".search.msn.com."},
	"yandexbot":   {".yandex.ru.", ".yandex.net.", ".yandex.com."},
	"baiduspider": {".baidu.com.", ".baidu.jp."},
	"duckduckbot": {".duckduckgo.com."},
	"slurp":       {".crawl.yahoo.net."},
	"facebot":     {".facebook.com.", ".fbsv.net."},
	"twitterbot":  {".twttr.com."},
	"applebot":    {".applebot.apple.com."},
	"linkedinbot": {".linkedin.com."},
}

// Known bad bot user-agent patterns.
var defaultDenyPatterns = []string{
	"semrushbot", "ahrefsbot", "mj12bot", "dotbot", "blexbot",
	"rogerbot", "megaindex", "serpstatbot", "zoominfobot",
	"dataforseo", "censys", "masscan", "zgrab",
}

// newBotDetectionState initializes the detection state from config.
func newBotDetectionState(config BotDetectionConfig) *botDetectionState {
	state := &botDetectionState{
		config:         config,
		goodBotDomains: make(map[string][]string),
		dnsCacheTTL:    10 * time.Minute,
	}

	// Build lowercased deny patterns
	for _, p := range config.DenyList {
		state.denyPatterns = append(state.denyPatterns, strings.ToLower(p))
	}
	// Add default deny patterns if the user did not provide a deny list
	if len(config.DenyList) == 0 {
		state.denyPatterns = append(state.denyPatterns, defaultDenyPatterns...)
	}

	// Build lowercased allow patterns
	for _, p := range config.AllowList {
		state.allowPatterns = append(state.allowPatterns, strings.ToLower(p))
	}

	// Copy default good bot domains
	for k, v := range defaultGoodBotDomains {
		state.goodBotDomains[k] = v
	}

	return state
}

// isAllowedBot checks if the user-agent matches an allow-listed bot pattern.
func (s *botDetectionState) isAllowedBot(ua string) (string, bool) {
	lowerUA := strings.ToLower(ua)
	for _, pattern := range s.allowPatterns {
		if strings.Contains(lowerUA, pattern) {
			return pattern, true
		}
	}
	// Check default good bots
	for botName := range s.goodBotDomains {
		if strings.Contains(lowerUA, botName) {
			return botName, true
		}
	}
	return "", false
}

// isDeniedBot checks if the user-agent matches a deny-listed bot pattern.
func (s *botDetectionState) isDeniedBot(ua string) (string, bool) {
	lowerUA := strings.ToLower(ua)
	for _, pattern := range s.denyPatterns {
		if strings.Contains(lowerUA, pattern) {
			return pattern, true
		}
	}
	return "", false
}

// verifyGoodBot performs reverse DNS verification to confirm a bot is legitimate.
// For example, a request claiming to be Googlebot should resolve to *.googlebot.com.
func (s *botDetectionState) verifyGoodBot(ctx context.Context, remoteAddr string, botName string) bool {
	if !s.config.VerifyGoodBot {
		return true // skip verification if not enabled
	}

	expectedSuffixes, ok := s.goodBotDomains[botName]
	if !ok {
		return true // no known domains to verify against, allow through
	}

	// Extract IP from remote address
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	// Check DNS cache
	if entry, ok := s.dnsCache.Load(ip); ok {
		cached := entry.(*dnsCacheEntry)
		if time.Now().Before(cached.expiresAt) {
			return matchesDNSSuffix(cached.hostnames, expectedSuffixes)
		}
		s.dnsCache.Delete(ip)
	}

	// Perform reverse DNS lookup with timeout
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resolver := net.DefaultResolver
	hostnames, err := resolver.LookupAddr(lookupCtx, ip)
	if err != nil {
		slog.Debug("reverse DNS lookup failed for good bot verification",
			"ip", ip, "bot", botName, "error", err)
		return false
	}

	// Cache the result
	s.dnsCache.Store(ip, &dnsCacheEntry{
		hostnames: hostnames,
		expiresAt: time.Now().Add(s.dnsCacheTTL),
	})

	if !matchesDNSSuffix(hostnames, expectedSuffixes) {
		slog.Warn("good bot verification failed: reverse DNS does not match expected domains",
			"ip", ip, "bot", botName, "hostnames", hostnames, "expected_suffixes", expectedSuffixes)
		return false
	}

	// Forward DNS verification: confirm the hostname resolves back to the same IP
	for _, hostname := range hostnames {
		for _, suffix := range expectedSuffixes {
			if strings.HasSuffix(hostname, suffix) {
				addrs, err := resolver.LookupHost(lookupCtx, strings.TrimSuffix(hostname, "."))
				if err != nil {
					continue
				}
				for _, addr := range addrs {
					if addr == ip {
						return true
					}
				}
			}
		}
	}

	slog.Warn("good bot verification failed: forward DNS does not match",
		"ip", ip, "bot", botName, "hostnames", hostnames)
	return false
}

// matchesDNSSuffix checks if any hostname ends with any of the expected suffixes.
func matchesDNSSuffix(hostnames []string, suffixes []string) bool {
	for _, h := range hostnames {
		for _, s := range suffixes {
			if strings.HasSuffix(h, s) {
				return true
			}
		}
	}
	return false
}

// BotDetectionMiddleware creates middleware that detects and handles bot traffic.
// It checks User-Agent against allow/deny lists, optionally verifies good bots via
// reverse DNS, and takes action based on the configured mode (block, challenge, log).
func BotDetectionMiddleware(config *BotDetectionConfig) func(http.Handler) http.Handler {
	if config == nil || !config.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}

	// Normalize mode
	mode := strings.ToLower(config.Mode)
	if mode == "" {
		mode = "log"
	}

	challengeType := strings.ToLower(config.ChallengeType)
	if challengeType == "" {
		challengeType = "js"
	}

	state := newBotDetectionState(*config)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ua := r.UserAgent()

			// Check allow list first (good bots get through unless verification fails)
			if botName, allowed := state.isAllowedBot(ua); allowed {
				if state.config.VerifyGoodBot {
					verified := state.verifyGoodBot(r.Context(), r.RemoteAddr, botName)
					if !verified {
						slog.Warn("bot claims to be good bot but failed DNS verification",
							"bot", botName, "remote_addr", r.RemoteAddr, "user_agent", ua)
						metric.BotDetection("impersonator", mode)
						blocked := handleBotAction(w, r, mode, challengeType, botName+" (unverified)")
						if blocked {
							return
						}
						next.ServeHTTP(w, r)
						return
					}
				}
				slog.Debug("allowed good bot", "bot", botName, "remote_addr", r.RemoteAddr)
				metric.BotDetection("good_bot", "allow")
				next.ServeHTTP(w, r)
				return
			}

			// Check deny list
			if pattern, denied := state.isDeniedBot(ua); denied {
				slog.Info("denied bot detected",
					"pattern", pattern, "remote_addr", r.RemoteAddr, "user_agent", ua)
				metric.BotDetection("bad_bot", mode)
				blocked := handleBotAction(w, r, mode, challengeType, pattern)
				if blocked {
					return
				}
			}

			// No match on either list, or log mode - allow through
			next.ServeHTTP(w, r)
		})
	}
}

// handleBotAction takes the configured action against a detected bot.
// Returns true if the request was blocked (caller should not continue to next handler).
func handleBotAction(w http.ResponseWriter, r *http.Request, mode, challengeType, botPattern string) bool {
	switch mode {
	case "block":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Access Denied")
		return true

	case "challenge":
		serveChallengePage(w, r, challengeType)
		return true

	case "log":
		// Log-only mode: record the detection but allow the request through
		slog.Info("bot detected (log mode, allowing through)",
			"pattern", botPattern,
			"remote_addr", r.RemoteAddr,
			"path", r.URL.Path,
			"user_agent", r.UserAgent())
		return false

	default:
		// Unknown mode, fall back to log
		slog.Warn("unknown bot detection mode, falling back to log",
			"mode", mode, "pattern", botPattern)
		return false
	}
}

// serveChallengePage returns a challenge page to verify the client is not a bot.
func serveChallengePage(w http.ResponseWriter, _ *http.Request, challengeType string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusForbidden)

	switch challengeType {
	case "captcha":
		fmt.Fprint(w, captchaChallengePage)
	default: // "js"
		fmt.Fprint(w, jsChallengePage)
	}
}

// jsChallengePage is a simple JavaScript challenge that bots without JS engines cannot pass.
// The page sets a cookie via JavaScript and redirects. Clients that support JavaScript
// will automatically reload with the cookie set, and subsequent requests pass through.
const jsChallengePage = `<!DOCTYPE html>
<html>
<head>
<title>Checking your browser</title>
<style>
body { font-family: sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
.container { max-width: 400px; margin: 0 auto; padding: 30px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.spinner { border: 4px solid #e0e0e0; border-top: 4px solid #333; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="container">
<div class="spinner"></div>
<h2>Checking your browser</h2>
<p>This process is automatic. Your browser will redirect shortly.</p>
<noscript><p>Please enable JavaScript to continue.</p></noscript>
</div>
<script>
(function(){
  var ts = Date.now();
  var v = ts.toString(36) + Math.random().toString(36).substr(2,6);
  document.cookie = "_sb_bot_check=" + v + "; path=/; max-age=3600; SameSite=Strict";
  setTimeout(function(){ window.location.reload(); }, 1500);
})();
</script>
</body>
</html>`

// captchaChallengePage provides a placeholder CAPTCHA challenge page.
// In production, this would integrate with a CAPTCHA provider.
const captchaChallengePage = `<!DOCTYPE html>
<html>
<head>
<title>Verification Required</title>
<style>
body { font-family: sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
.container { max-width: 400px; margin: 0 auto; padding: 30px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
</style>
</head>
<body>
<div class="container">
<h2>Verification Required</h2>
<p>Please verify that you are not a robot.</p>
<noscript><p>Please enable JavaScript to continue.</p></noscript>
</div>
</body>
</html>`

// BotDetectionResult holds the result for metrics and logging.
type BotDetectionResult struct {
	IsBot    bool
	Category string // "good_bot", "bad_bot", "impersonator", "unknown"
	Pattern  string // matched pattern
	Verified bool   // DNS verification result (for good bots)
}

// SortedBotPatterns returns a sorted copy of patterns for deterministic output.
func SortedBotPatterns(patterns []string) []string {
	sorted := make([]string, len(patterns))
	copy(sorted, patterns)
	sort.Strings(sorted)
	return sorted
}
