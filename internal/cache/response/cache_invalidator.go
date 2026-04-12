// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// CacheInvalidator provides cache invalidation capabilities across all cache tiers
type CacheInvalidator struct {
	l1Cache cacher.Cacher // Memory cache
	l2Cache cacher.Cacher // Redis cache
	l3Cache cacher.Cacher // Filesystem cache

	// Metrics
	mu                sync.RWMutex
	invalidationCount int64
	lastInvalidation  time.Time

	// Tagging support
	tags map[string][]string // tag -> cache keys
}

// NewCacheInvalidator creates a new cache invalidator
func NewCacheInvalidator(l1, l2, l3 cacher.Cacher) *CacheInvalidator {
	return &CacheInvalidator{
		l1Cache: l1,
		l2Cache: l2,
		l3Cache: l3,
		tags:    make(map[string][]string),
	}
}

// InvalidateKey invalidates a specific cache key across all tiers
func (ci *CacheInvalidator) InvalidateKey(ctx context.Context, cacheType, key string) error {
	slog.Info("invalidating cache key",
		"type", cacheType,
		"key", key)

	start := time.Now()
	var errors []error

	// Invalidate in L3 (filesystem)
	if ci.l3Cache != nil {
		if err := ci.l3Cache.Delete(ctx, cacheType, key); err != nil {
			slog.Warn("failed to invalidate L3 cache", "error", err)
			errors = append(errors, fmt.Errorf("L3: %w", err))
		}
	}

	// Invalidate in L2 (Redis)
	if ci.l2Cache != nil {
		if err := ci.l2Cache.Delete(ctx, cacheType, key); err != nil {
			slog.Warn("failed to invalidate L2 cache", "error", err)
			errors = append(errors, fmt.Errorf("L2: %w", err))
		}
	}

	// Invalidate in L1 (memory)
	// L1 is per-instance, so this only affects local instance
	if ci.l1Cache != nil {
		if err := ci.l1Cache.Delete(ctx, cacheType, key); err != nil {
			slog.Warn("failed to invalidate L1 cache", "error", err)
			errors = append(errors, fmt.Errorf("L1: %w", err))
		}
	}

	ci.mu.Lock()
	ci.invalidationCount++
	ci.lastInvalidation = time.Now()
	ci.mu.Unlock()

	slog.Info("cache key invalidated",
		"type", cacheType,
		"key", key,
		"duration", time.Since(start),
		"errors", len(errors))

	if len(errors) > 0 {
		return fmt.Errorf("invalidation completed with %d errors: %v", len(errors), errors)
	}

	return nil
}

// InvalidatePattern invalidates all keys matching a pattern
func (ci *CacheInvalidator) InvalidatePattern(ctx context.Context, cacheType, pattern string) error {
	slog.Info("invalidating cache pattern",
		"type", cacheType,
		"pattern", pattern)

	start := time.Now()
	var errors []error

	// L3 invalidation
	if ci.l3Cache != nil {
		if err := ci.l3Cache.DeleteByPattern(ctx, cacheType, pattern); err != nil {
			slog.Warn("failed to invalidate L3 pattern", "error", err)
			errors = append(errors, fmt.Errorf("L3: %w", err))
		}
	}

	// L2 invalidation
	if ci.l2Cache != nil {
		if err := ci.l2Cache.DeleteByPattern(ctx, cacheType, pattern); err != nil {
			slog.Warn("failed to invalidate L2 pattern", "error", err)
			errors = append(errors, fmt.Errorf("L2: %w", err))
		}
	}

	// L1 invalidation
	if ci.l1Cache != nil {
		if err := ci.l1Cache.DeleteByPattern(ctx, cacheType, pattern); err != nil {
			slog.Warn("failed to invalidate L1 pattern", "error", err)
			errors = append(errors, fmt.Errorf("L1: %w", err))
		}
	}

	ci.mu.Lock()
	ci.invalidationCount++
	ci.lastInvalidation = time.Now()
	ci.mu.Unlock()

	slog.Info("cache pattern invalidated",
		"type", cacheType,
		"pattern", pattern,
		"duration", time.Since(start),
		"errors", len(errors))

	if len(errors) > 0 {
		return fmt.Errorf("pattern invalidation completed with %d errors: %v", len(errors), errors)
	}

	return nil
}

// InvalidatePrefix invalidates all keys with a given prefix
func (ci *CacheInvalidator) InvalidatePrefix(ctx context.Context, cacheType, prefix string) error {
	pattern := fmt.Sprintf("%s*", prefix)
	return ci.InvalidatePattern(ctx, cacheType, pattern)
}

// InvalidateAll invalidates all entries for a cache type
func (ci *CacheInvalidator) InvalidateAll(ctx context.Context, cacheType string) error {
	slog.Warn("invalidating all cache entries",
		"type", cacheType)

	return ci.InvalidatePattern(ctx, cacheType, "*")
}

// TagKey associates a cache key with one or more tags
func (ci *CacheInvalidator) TagKey(key string, tags ...string) {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	for _, tag := range tags {
		if ci.tags[tag] == nil {
			ci.tags[tag] = make([]string, 0)
		}
		ci.tags[tag] = append(ci.tags[tag], key)
	}

	slog.Debug("tagged cache key",
		"key", key,
		"tags", tags)
}

// InvalidateByTag invalidates all cache keys associated with a tag
func (ci *CacheInvalidator) InvalidateByTag(ctx context.Context, cacheType, tag string) error {
	ci.mu.RLock()
	keys, exists := ci.tags[tag]
	ci.mu.RUnlock()

	if !exists || len(keys) == 0 {
		slog.Debug("no keys found for tag", "tag", tag)
		return nil
	}

	slog.Info("invalidating by tag",
		"tag", tag,
		"keys", len(keys))

	var errors []error
	for _, key := range keys {
		if err := ci.InvalidateKey(ctx, cacheType, key); err != nil {
			errors = append(errors, err)
		}
	}

	// Remove tag after invalidation
	ci.mu.Lock()
	delete(ci.tags, tag)
	ci.mu.Unlock()

	if len(errors) > 0 {
		return fmt.Errorf("tag invalidation completed with %d errors", len(errors))
	}

	return nil
}

// InvalidateByTags invalidates cache keys matching any of the provided tags
func (ci *CacheInvalidator) InvalidateByTags(ctx context.Context, cacheType string, tags ...string) error {
	slog.Info("invalidating by multiple tags", "tags", tags)

	var allErrors []error
	for _, tag := range tags {
		if err := ci.InvalidateByTag(ctx, cacheType, tag); err != nil {
			allErrors = append(allErrors, err)
		}
	}

	if len(allErrors) > 0 {
		return fmt.Errorf("multi-tag invalidation completed with %d errors", len(allErrors))
	}

	return nil
}

// GetStats returns invalidation statistics
func (ci *CacheInvalidator) GetStats() InvalidationStats {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	return InvalidationStats{
		TotalInvalidations: ci.invalidationCount,
		LastInvalidation:   ci.lastInvalidation,
		TotalTags:          len(ci.tags),
	}
}

// InvalidationStats contains invalidation statistics
type InvalidationStats struct {
	TotalInvalidations int64
	LastInvalidation   time.Time
	TotalTags          int
}

// VersionedCacheKey creates a versioned cache key
func VersionedCacheKey(version, key string) string {
	return fmt.Sprintf("v%s:%s", version, key)
}

// ParseVersionedKey extracts version and key from a versioned cache key
func ParseVersionedKey(versionedKey string) (version, key string) {
	if !strings.HasPrefix(versionedKey, "v") {
		return "", versionedKey
	}

	parts := strings.SplitN(versionedKey, ":", 2)
	if len(parts) != 2 {
		return "", versionedKey
	}

	version = strings.TrimPrefix(parts[0], "v")
	key = parts[1]

	return version, key
}

// InvalidateVersion invalidates all cache entries for a specific version
func (ci *CacheInvalidator) InvalidateVersion(ctx context.Context, cacheType, version string) error {
	slog.Info("invalidating cache version",
		"type", cacheType,
		"version", version)

	pattern := fmt.Sprintf("v%s:*", version)
	return ci.InvalidatePattern(ctx, cacheType, pattern)
}

// CacheInvalidationRequest represents a cache invalidation request
type CacheInvalidationRequest struct {
	Type    string   `json:"type"`    // Cache type (response, action, callback)
	Method  string   `json:"method"`  // invalidate_key, invalidate_pattern, invalidate_tag, invalidate_version
	Key     string   `json:"key"`     // For invalidate_key
	Pattern string   `json:"pattern"` // For invalidate_pattern
	Tags    []string `json:"tags"`    // For invalidate_tag
	Version string   `json:"version"` // For invalidate_version
	DryRun  bool     `json:"dry_run"` // If true, only report what would be invalidated
}

// CacheInvalidationResponse represents the response to an invalidation request
type CacheInvalidationResponse struct {
	Success     bool     `json:"success"`
	Message     string   `json:"message"`
	Invalidated int      `json:"invalidated"` // Number of keys invalidated
	Errors      []string `json:"errors,omitempty"`
	Duration    string   `json:"duration"`
}

// Execute executes a cache invalidation request
func (ci *CacheInvalidator) Execute(ctx context.Context, req CacheInvalidationRequest) (*CacheInvalidationResponse, error) {
	start := time.Now()

	if req.DryRun {
		slog.Info("dry-run invalidation request",
			"type", req.Type,
			"method", req.Method)

		return &CacheInvalidationResponse{
			Success:  true,
			Message:  fmt.Sprintf("Dry-run: would invalidate %s with method %s", req.Type, req.Method),
			Duration: time.Since(start).String(),
		}, nil
	}

	var err error

	switch req.Method {
	case "invalidate_key":
		err = ci.InvalidateKey(ctx, req.Type, req.Key)
	case "invalidate_pattern":
		err = ci.InvalidatePattern(ctx, req.Type, req.Pattern)
	case "invalidate_prefix":
		err = ci.InvalidatePrefix(ctx, req.Type, req.Pattern)
	case "invalidate_tag":
		if len(req.Tags) == 0 {
			return nil, fmt.Errorf("no tags provided")
		}
		err = ci.InvalidateByTags(ctx, req.Type, req.Tags...)
	case "invalidate_version":
		err = ci.InvalidateVersion(ctx, req.Type, req.Version)
	case "invalidate_all":
		err = ci.InvalidateAll(ctx, req.Type)
	default:
		return nil, fmt.Errorf("unknown invalidation method: %s", req.Method)
	}

	resp := &CacheInvalidationResponse{
		Success:     err == nil,
		Invalidated: 1,
		Duration:    time.Since(start).String(),
	}

	if err != nil {
		resp.Message = fmt.Sprintf("Invalidation failed: %v", err)
		resp.Errors = []string{err.Error()}
	} else {
		resp.Message = fmt.Sprintf("Successfully invalidated %s cache", req.Type)
	}

	return resp, err
}
