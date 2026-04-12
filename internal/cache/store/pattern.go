// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

// matchPattern checks if a key matches a pattern using simple wildcard matching.
// Supports "*" (match all), exact match, and prefix matching with trailing "*".
// If the pattern has no trailing "*", it is treated as a prefix match.
func matchPattern(key, pattern string) (bool, error) {
	if pattern == "*" {
		return true, nil
	}
	if pattern == key {
		return true, nil
	}
	// Trailing wildcard: prefix match
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(key) >= len(prefix) && key[:len(prefix)] == prefix, nil
	}
	// No wildcard: treat as prefix match
	return len(key) >= len(pattern) && key[:len(pattern)] == pattern, nil
}
