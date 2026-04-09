// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ExactStore provides a simple key-value interface for exact-match caching.
type ExactStore interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
}

// ExactMatchConfig configures the exact-match cache fast path.
type ExactMatchConfig struct {
	Enabled bool            `json:"enabled,omitempty"`
	TTL     reqctx.Duration `json:"ttl,omitempty"`
}

// ExactMatchCache provides a fast SHA256-based exact-match cache layer
// that sits in front of the slower semantic similarity search.
type ExactMatchCache struct {
	store   ExactStore
	enabled bool
	ttl     time.Duration
}

// NewExactMatchCache creates a new exact-match cache.
func NewExactMatchCache(cfg ExactMatchConfig, store ExactStore) *ExactMatchCache {
	ttl := cfg.TTL.Duration
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &ExactMatchCache{
		store:   store,
		enabled: cfg.Enabled,
		ttl:     ttl,
	}
}

// Lookup checks the exact-match cache for a response matching the model and content.
// Returns the cached response bytes and true on hit, or nil and false on miss.
func (c *ExactMatchCache) Lookup(ctx context.Context, model, content string) ([]byte, bool) {
	if !c.enabled || c.store == nil {
		return nil, false
	}

	key := exactCacheKey(model, content)
	data, err := c.store.Get(ctx, key)
	if err != nil || len(data) == 0 {
		return nil, false
	}

	slog.Debug("exact cache hit", "model", model, "key_prefix", key[:16])
	return data, true
}

// Store saves a response in the exact-match cache keyed by model and content.
func (c *ExactMatchCache) Store(ctx context.Context, model, content string, response []byte) {
	if !c.enabled || c.store == nil {
		return
	}

	key := exactCacheKey(model, content)
	if err := c.store.Set(ctx, key, response, c.ttl); err != nil {
		slog.Debug("exact cache store error", "error", err)
	}
}

// exactCacheKey generates a deterministic cache key from model and normalized content.
func exactCacheKey(model, content string) string {
	normalized := normalizeContent(content)
	h := sha256.Sum256([]byte(model + "\n" + normalized))
	return fmt.Sprintf("exact:%x", h)
}

// normalizeContent normalizes prompt content for consistent cache key generation.
// Trims whitespace and lowercases the content.
func normalizeContent(content string) string {
	return strings.ToLower(strings.TrimSpace(content))
}

// MemoryExactStore is a simple in-memory implementation of ExactStore for testing
// and lightweight deployments.
type MemoryExactStore struct {
	entries map[string]memoryExactEntry
}

type memoryExactEntry struct {
	data      []byte
	expiresAt time.Time
}

// NewMemoryExactStore creates a new in-memory exact store.
func NewMemoryExactStore() *MemoryExactStore {
	return &MemoryExactStore{
		entries: make(map[string]memoryExactEntry),
	}
}

// Get retrieves a value by key. Returns an error if not found or expired.
func (s *MemoryExactStore) Get(_ context.Context, key string) ([]byte, error) {
	entry, ok := s.entries[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		delete(s.entries, key)
		return nil, fmt.Errorf("expired")
	}
	return entry.data, nil
}

// Set stores a value with an optional TTL.
func (s *MemoryExactStore) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}
	s.entries[key] = memoryExactEntry{
		data:      append([]byte(nil), value...), // defensive copy
		expiresAt: expiresAt,
	}
	return nil
}

// ExactCacheKeyForTest exposes exactCacheKey for testing.
func ExactCacheKeyForTest(model, content string) string {
	return exactCacheKey(model, content)
}

// NormalizeContentForTest exposes normalizeContent for testing.
func NormalizeContentForTest(content string) string {
	return normalizeContent(content)
}

// MarshalResponse marshals a response for exact cache storage.
func MarshalResponse(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// UnmarshalResponse unmarshals a response from exact cache storage.
func UnmarshalResponse(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
