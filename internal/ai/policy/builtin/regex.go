package builtin

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// RegexDetector detects content matching custom regex patterns.
// Config fields: "patterns" ([]string) - list of regex patterns to match.
type RegexDetector struct {
	cache map[string]*regexp.Regexp
	mu    sync.RWMutex
}

// NewRegexDetector creates a regex detector with a compiled pattern cache.
func NewRegexDetector() *RegexDetector {
	return &RegexDetector{
		cache: make(map[string]*regexp.Regexp),
	}
}

// Detect checks content against configured regex patterns.
func (d *RegexDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	patterns, _ := toStringSlice(config.Config["patterns"])

	var matched []string
	for _, pattern := range patterns {
		re, err := d.getOrCompile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}
		if re.MatchString(content) {
			matched = append(matched, pattern)
		}
	}

	if len(matched) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("matched patterns: %s", strings.Join(matched, ", "))
	}

	result.Latency = time.Since(start)
	return result, nil
}

func (d *RegexDetector) getOrCompile(pattern string) (*regexp.Regexp, error) {
	d.mu.RLock()
	re, ok := d.cache[pattern]
	d.mu.RUnlock()
	if ok {
		return re, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if re, ok := d.cache[pattern]; ok {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	d.cache[pattern] = re
	return re, nil
}
