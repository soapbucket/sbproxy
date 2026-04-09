package builtin

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// URLDetector detects and validates URLs in content. Checks against a malicious domain blocklist.
// Config fields:
//   - "blocked_domains" ([]string) - list of blocked domains
//   - "require_https" (bool) - if true, only HTTPS URLs are allowed
//   - "mode" (string) - "block" (trigger on bad URLs) or "detect" (trigger on any URL)
type URLDetector struct{}

var urlRegex = regexp.MustCompile(`https?://[^\s<>\"'\)]+`)

// Detect checks content for URLs and validates them.
func (d *URLDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	blockedDomains, _ := toStringSlice(config.Config["blocked_domains"])
	requireHTTPS, _ := toBool(config.Config["require_https"])
	mode, _ := toString(config.Config["mode"])
	if mode == "" {
		mode = "block"
	}

	blockedSet := make(map[string]bool, len(blockedDomains))
	for _, d := range blockedDomains {
		blockedSet[strings.ToLower(d)] = true
	}

	matches := urlRegex.FindAllString(content, -1)

	if mode == "detect" && len(matches) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("detected %d URL(s)", len(matches))
		result.Latency = time.Since(start)
		return result, nil
	}

	var issues []string
	for _, rawURL := range matches {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			issues = append(issues, fmt.Sprintf("invalid URL: %s", rawURL))
			continue
		}

		if requireHTTPS && parsed.Scheme != "https" {
			issues = append(issues, fmt.Sprintf("non-HTTPS URL: %s", rawURL))
			continue
		}

		host := strings.ToLower(parsed.Hostname())
		if blockedSet[host] {
			issues = append(issues, fmt.Sprintf("blocked domain: %s", host))
			continue
		}

		// Check parent domains.
		parts := strings.Split(host, ".")
		for i := 1; i < len(parts)-1; i++ {
			parent := strings.Join(parts[i:], ".")
			if blockedSet[parent] {
				issues = append(issues, fmt.Sprintf("blocked domain: %s (parent: %s)", host, parent))
				break
			}
		}
	}

	if len(issues) > 0 {
		result.Triggered = true
		result.Details = strings.Join(issues, "; ")
	}

	result.Latency = time.Since(start)
	return result, nil
}
