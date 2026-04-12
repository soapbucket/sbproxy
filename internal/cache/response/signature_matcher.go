// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/cespare/xxhash/v2"
	"github.com/soapbucket/sbproxy/internal/config"
)

// SignatureMatcher matches response data against configured signature patterns
type SignatureMatcher struct {
	patterns        []config.SignaturePattern
	compiledRegexes map[int]*regexp.Regexp // Cache compiled regexes by pattern index
}

// NewSignatureMatcher creates a new signature matcher with the given patterns
func NewSignatureMatcher(patterns []config.SignaturePattern) (*SignatureMatcher, error) {
	sm := &SignatureMatcher{
		patterns:        patterns,
		compiledRegexes: make(map[int]*regexp.Regexp),
	}

	// Pre-compile regex patterns
	for i, pattern := range patterns {
		if pattern.PatternType == "regex" && pattern.RegexPattern != "" {
			re, err := regexp.Compile(pattern.RegexPattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern for signature %q: %w", pattern.Name, err)
			}
			sm.compiledRegexes[i] = re
		}
	}

	return sm, nil
}

// Match attempts to match data against all configured patterns
// Returns the first matching pattern and the prefix length, or (nil, 0) if no match
func (sm *SignatureMatcher) Match(data []byte) (*config.SignaturePattern, int) {
	for i := range sm.patterns {
		pattern := &sm.patterns[i]

		var matched bool
		var prefixLen int

		switch pattern.PatternType {
		case "exact":
			matched, prefixLen = sm.matchExact(data, pattern)
		case "regex":
			matched, prefixLen = sm.matchRegex(data, pattern, i)
		case "hash":
			matched, prefixLen = sm.matchHash(data, pattern)
		default:
			// Unknown pattern type, skip
			continue
		}

		if matched {
			return pattern, prefixLen
		}
	}

	return nil, 0
}

// matchExact checks if data starts with the exact bytes specified in the pattern
func (sm *SignatureMatcher) matchExact(data []byte, pattern *config.SignaturePattern) (bool, int) {
	if pattern.ExactBytes == "" {
		return false, 0
	}

	// Decode base64-encoded bytes
	exactBytes, err := base64.StdEncoding.DecodeString(pattern.ExactBytes)
	if err != nil {
		return false, 0
	}

	// Check if data starts with exact bytes
	if !bytes.HasPrefix(data, exactBytes) {
		return false, 0
	}

	// Determine prefix length
	prefixLen := determinePrefixLength(data, pattern)
	return true, prefixLen
}

// matchRegex checks if data matches the regex pattern
func (sm *SignatureMatcher) matchRegex(data []byte, pattern *config.SignaturePattern, patternIndex int) (bool, int) {
	re, ok := sm.compiledRegexes[patternIndex]
	if !ok {
		return false, 0
	}

	// Find match location
	loc := re.FindIndex(data)
	if loc == nil || loc[0] != 0 {
		// No match or doesn't start at beginning
		return false, 0
	}

	// Determine prefix length
	prefixLen := determinePrefixLength(data, pattern)
	return true, prefixLen
}

// matchHash checks if the hash of the first N bytes matches the expected hash
func (sm *SignatureMatcher) matchHash(data []byte, pattern *config.SignaturePattern) (bool, int) {
	if pattern.HashLength == 0 || pattern.HashAlgorithm == "" || pattern.HashPattern == "" {
		return false, 0
	}

	// Check if we have enough data
	if len(data) < pattern.HashLength {
		return false, 0
	}

	// Hash the first N bytes
	hashData := data[:pattern.HashLength]
	var hash string

	switch pattern.HashAlgorithm {
	case "xxhash":
		h := xxhash.New()
		_, _ = h.Write(hashData)
		hash = fmt.Sprintf("%x", h.Sum64())

	case "sha256":
		h := sha256.Sum256(hashData)
		hash = fmt.Sprintf("%x", h)

	default:
		// Unknown algorithm
		return false, 0
	}

	// Compare hashes
	if hash != pattern.HashPattern {
		return false, 0
	}

	// Determine prefix length
	prefixLen := determinePrefixLength(data, pattern)
	return true, prefixLen
}

// determinePrefixLength determines how much of the response should be cached as a prefix
// Tries to find a logical boundary and respects min/max constraints
func determinePrefixLength(data []byte, pattern *config.SignaturePattern) int {
	maxExamine := len(data)

	// Apply pattern-specific max examine bytes
	if pattern.MaxExamineBytes > 0 && pattern.MaxExamineBytes < maxExamine {
		maxExamine = pattern.MaxExamineBytes
	}

	// Find a logical boundary (e.g., end of HTML <head> tag)
	prefixLen := findLogicalBoundary(data[:maxExamine])

	// Apply minimum constraint
	if pattern.MinPrefixLength > 0 && prefixLen < pattern.MinPrefixLength {
		prefixLen = pattern.MinPrefixLength
		if prefixLen > maxExamine {
			prefixLen = maxExamine
		}
	}

	// Apply maximum constraint
	if pattern.MaxPrefixLength > 0 && prefixLen > pattern.MaxPrefixLength {
		prefixLen = pattern.MaxPrefixLength
	}

	return prefixLen
}

// findLogicalBoundary attempts to find a logical boundary in HTML content
// Returns the position after </head> if found, otherwise returns len(data)
func findLogicalBoundary(data []byte) int {
	// Look for </head> tag as a common boundary
	headEnd := bytes.Index(data, []byte("</head>"))
	if headEnd != -1 {
		// Return position after the tag
		return headEnd + len("</head>")
	}

	// Look for <body> tag as alternative
	bodyStart := bytes.Index(data, []byte("<body"))
	if bodyStart != -1 {
		return bodyStart
	}

	// No logical boundary found, return all examined data
	return len(data)
}
