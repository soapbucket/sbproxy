// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ChunkCacheConfig defines the configuration for chunk caching middleware
// Supports both URL-based and signature-based (fingerprint) caching
// If ChunkCacheConfig is present (not nil), chunk caching is enabled
type ChunkCacheConfig struct {
	// URL-based caching (cache by request URL)
	URLCache URLCacheConfig `json:"url_cache,omitempty"`

	// Signature-based caching (cache by response signature/fingerprint)
	SignatureCache SignatureCacheConfig `json:"signature_cache,omitempty"`

	// Ignore Cache-Control: no-cache header from client
	IgnoreNoCache bool `json:"ignore_no_cache,omitempty"`
}

// URLCacheConfig defines URL-based chunk caching
type URLCacheConfig struct {
	Enabled bool            `json:"enabled"`
	TTL     reqctx.Duration `json:"ttl,omitempty"` // Default: 1h
}

// SignatureCacheConfig defines signature-based chunk caching (fingerprint)
// Caches response prefixes based on matching signatures in the response body
type SignatureCacheConfig struct {
	Enabled bool `json:"enabled"`

	// Content types to examine for signature matching
	ContentTypes []string `json:"content_types,omitempty"` // Default: ["text/html"]

	// Signature patterns to match against response prefixes
	Signatures []SignaturePattern `json:"signatures,omitempty"`

	// Maximum bytes to examine for signature matching
	MaxExamineBytes int `json:"max_examine_bytes,omitempty"` // Default: 8192

	// Default TTL for cached prefixes (can be overridden per signature)
	DefaultTTL reqctx.Duration `json:"default_ttl,omitempty"` // Default: 30m
}

// SignaturePattern defines a pattern to match in response bodies
type SignaturePattern struct {
	// Human-readable name for this signature
	Name string `json:"name"`

	// Pattern type: "exact", "regex", "hash"
	PatternType string `json:"pattern_type"`

	// For "exact" type: Base64-encoded bytes to match at start of response
	ExactBytes string `json:"exact_bytes,omitempty"`

	// For "regex" type: Regular expression to match
	RegexPattern string `json:"regex_pattern,omitempty"`

	// For "hash" type: Expected hash value
	HashPattern string `json:"hash_pattern,omitempty"`

	// For "hash" type: Number of bytes to hash
	HashLength int `json:"hash_length,omitempty"`

	// For "hash" type: Hash algorithm ("xxhash", "sha256")
	HashAlgorithm string `json:"hash_algorithm,omitempty"`

	// Maximum bytes to examine for this signature (overrides global)
	MaxExamineBytes int `json:"max_examine_bytes,omitempty"`

	// TTL for this signature's cached prefix (overrides default)
	CacheTTL reqctx.Duration `json:"cache_ttl,omitempty"`

	// Minimum length of prefix to cache
	MinPrefixLength int `json:"min_prefix_length,omitempty"`

	// Maximum length of prefix to cache
	MaxPrefixLength int `json:"max_prefix_length,omitempty"`
}

