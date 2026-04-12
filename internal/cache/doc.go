// Package cache provides response caching with multiple storage backends.
//
// Subpackages implement object caching, origin-level caching, full
// response caching, and pluggable storage backends (in-memory, Redis).
// Cache keys are partitioned by workspace to ensure tenant isolation.
package cache
