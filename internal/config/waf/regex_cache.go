// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import (
	"fmt"
	"regexp"
	"sync"
)

const maxRegexCacheSize = 1000

// maxPatternLength limits individual regex pattern length to prevent
// excessive memory usage during compilation. Go's regexp uses RE2
// (linear time, no backtracking) so ReDoS CPU attacks are not possible,
// but very large patterns can still consume significant memory.
const maxPatternLength = 4096

var (
	regexCache   = make(map[string]*regexp.Regexp, 100)
	regexCacheMu sync.RWMutex
)

// getCompiledRegex gets or compiles a regex pattern with caching.
func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxPatternLength {
		return nil, fmt.Errorf("regex pattern too long (%d chars, max %d)", len(pattern), maxPatternLength)
	}

	regexCacheMu.RLock()
	if re, ok := regexCache[pattern]; ok {
		regexCacheMu.RUnlock()
		return re, nil
	}
	regexCacheMu.RUnlock()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCacheMu.Lock()
	if existing, ok := regexCache[pattern]; ok {
		regexCacheMu.Unlock()
		return existing, nil
	}
	if len(regexCache) < maxRegexCacheSize {
		regexCache[pattern] = re
	}
	regexCacheMu.Unlock()

	return re, nil
}
