// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import (
	"fmt"
	"regexp"

	"github.com/soapbucket/sbproxy/internal/util/lru"
)

const maxRegexCacheSize = 1000

// maxPatternLength limits individual regex pattern length to prevent
// excessive memory usage during compilation. Go's regexp uses RE2
// (linear time, no backtracking) so ReDoS CPU attacks are not possible,
// but very large patterns can still consume significant memory.
const maxPatternLength = 4096

// regexCache uses an LRU cache for automatic eviction of least-recently-used
// patterns instead of refusing new patterns once the cache is full.
var regexCache = lru.NewSharded[string, *regexp.Regexp](maxRegexCacheSize, nil)

// getCompiledRegex gets or compiles a regex pattern with caching.
func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxPatternLength {
		return nil, fmt.Errorf("regex pattern too long (%d chars, max %d)", len(pattern), maxPatternLength)
	}

	if re, ok := regexCache.Get(pattern); ok {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCache.Put(pattern, re)
	return re, nil
}
