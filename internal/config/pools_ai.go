// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import "sync"

// Additional buffer pools for AI transforms and PII scanning.
// Complements the core pools in pools.go.

var (
	// findingsSlicePool provides reusable slices for PII match results.
	findingsSlicePool = sync.Pool{
		New: func() interface{} {
			s := make([]string, 0, 16)
			return &s
		},
	}
)

// getFindingsSlice retrieves a string slice from the pool for collecting findings.
func getFindingsSlice() *[]string {
	return findingsSlicePool.Get().(*[]string)
}

// putFindingsSlice returns a string slice to the pool after resetting.
func putFindingsSlice(s *[]string) {
	if s == nil {
		return
	}
	if cap(*s) > 256 {
		return // discard oversized slices
	}
	*s = (*s)[:0]
	findingsSlicePool.Put(s)
}
