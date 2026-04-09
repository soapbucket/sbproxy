// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package cacher

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// CacheKeyBuilder provides a fluent interface for building cache keys
// Optimized to reduce string allocations using strings.Builder from pool
type CacheKeyBuilder struct {
	parts []string
}

// NewCacheKeyBuilder creates a new cache key builder
func NewCacheKeyBuilder() *CacheKeyBuilder {
	return &CacheKeyBuilder{
		parts: make([]string, 0, 8),
	}
}

// Add adds a part to the cache key
func (b *CacheKeyBuilder) Add(part string) *CacheKeyBuilder {
	b.parts = append(b.parts, part)
	return b
}

// AddRequest adds request method and URL to the cache key
func (b *CacheKeyBuilder) AddRequest(req *http.Request) *CacheKeyBuilder {
	return b.Add(req.Method).Add(req.URL.String())
}

// AddHeaders adds headers to the cache key
func (b *CacheKeyBuilder) AddHeaders(headers map[string]string) *CacheKeyBuilder {
	for k, v := range headers {
		b.Add(k).Add(v)
	}
	return b
}

// AddHeader adds a specific header to the cache key
func (b *CacheKeyBuilder) AddHeader(req *http.Request, name string) *CacheKeyBuilder {
	if value := req.Header.Get(name); value != "" {
		b.Add(name).Add(value)
	}
	return b
}

// Build returns the cache key as a colon-separated string
// Optimized to use strings.Builder from pool with pre-allocated capacity
func (b *CacheKeyBuilder) Build() string {
	if len(b.parts) == 0 {
		return ""
	}
	if len(b.parts) == 1 {
		return b.parts[0]
	}
	
	// Estimate capacity: sum of part lengths + separators
	capacity := 0
	for _, part := range b.parts {
		capacity += len(part)
	}
	capacity += len(b.parts) - 1 // separators
	
	// Get builder from pool with pre-allocated capacity
	// Uses adaptive pool sizing when available
	builder := GetBuilderWithSize(capacity)
	defer PutBuilder(builder)
	
	// Build the string
	builder.WriteString(b.parts[0])
	for i := 1; i < len(b.parts); i++ {
		builder.WriteByte(':')
		builder.WriteString(b.parts[i])
	}
	
	return builder.String()
}

// BuildHashed returns the cache key as a SHA-256 hash
// Optimized to hash directly from parts using builder from pool
func (b *CacheKeyBuilder) BuildHashed() string {
	if len(b.parts) == 0 {
		hash := sha256.Sum256(nil)
		return hex.EncodeToString(hash[:])
	}
	
	// Estimate capacity for hashing
	capacity := 0
	for _, part := range b.parts {
		capacity += len(part)
	}
	capacity += len(b.parts) - 1 // separators
	
	// Get builder from pool with pre-allocated capacity
	// Uses adaptive pool sizing when available
	builder := GetBuilderWithSize(capacity)
	defer PutBuilder(builder)
	
	builder.WriteString(b.parts[0])
	for i := 1; i < len(b.parts); i++ {
		builder.WriteByte(':')
		builder.WriteString(b.parts[i])
	}
	
	// Hash directly from builder's string
	keyBytes := []byte(builder.String())
	hash := sha256.Sum256(keyBytes)
	return hex.EncodeToString(hash[:])
}

// Common cache key patterns

// RequestCacheKey generates a cache key for an HTTP request
func RequestCacheKey(req *http.Request) string {
	return NewCacheKeyBuilder().
		AddRequest(req).
		BuildHashed()
}

// RequestCacheKeyWithHeaders generates a cache key including specific headers
func RequestCacheKeyWithHeaders(req *http.Request, headers ...string) string {
	builder := NewCacheKeyBuilder().AddRequest(req)
	for _, header := range headers {
		builder.AddHeader(req, header)
	}
	return builder.BuildHashed()
}

// SessionCacheKey generates a cache key for a session
func SessionCacheKey(sessionID string) string {
	return NewCacheKeyBuilder().
		Add("session").
		Add(sessionID).
		Build()
}

// CallbackCacheKey generates a cache key for a callback
func CallbackCacheKey(url string, method string) string {
	return NewCacheKeyBuilder().
		Add("callback").
		Add(method).
		Add(url).
		BuildHashed()
}

// TokenCacheKey generates a cache key for a token
func TokenCacheKey(tokenType, token string) string {
	return NewCacheKeyBuilder().
		Add("token").
		Add(tokenType).
		Add(token).
		BuildHashed()
}

// OriginCacheKey generates a cache key for an origin configuration
func OriginCacheKey(hostname string) string {
	return NewCacheKeyBuilder().
		Add("origin").
		Add(hostname).
		Build()
}

