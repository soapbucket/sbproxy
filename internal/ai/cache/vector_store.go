// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"context"
	"time"
)

// CacheHealth reports the health status of a cache backend.
type CacheHealth struct {
	StoreType string `json:"store_type"`
	Entries   int64  `json:"entries"`
	Capacity  int    `json:"capacity"`
	Healthy   bool   `json:"healthy"`
	Error     string `json:"error,omitempty"`
}

// VectorStore provides vector similarity search operations.
type VectorStore interface {
	// Search finds the most similar vectors to the query.
	// Returns entries with similarity >= threshold, sorted by similarity descending.
	Search(ctx context.Context, embedding []float32, threshold float64, limit int) ([]VectorEntry, error)

	// Store adds a vector entry to the store.
	Store(ctx context.Context, entry VectorEntry) error

	// Delete removes an entry by key.
	Delete(ctx context.Context, key string) error

	// Size returns the number of entries in the store.
	Size(ctx context.Context) (int64, error)

	// Health returns the health status of the store backend.
	Health(ctx context.Context) CacheHealth
}

// VectorEntry represents a cached vector entry.
type VectorEntry struct {
	Key        string        `json:"key"`
	Namespace  string        `json:"namespace,omitempty"`
	Embedding  []float32     `json:"embedding"`
	Response   []byte        `json:"response"`
	Model      string        `json:"model"`
	CreatedAt  time.Time     `json:"created_at"`
	LastAccess time.Time     `json:"last_access"` // Track access time for LRU eviction
	TTL        time.Duration `json:"ttl"`
	Similarity float64       `json:"similarity,omitempty"`
}

// IsExpired returns true if the entry has exceeded its TTL.
func (e *VectorEntry) IsExpired() bool {
	if e.TTL <= 0 {
		return false
	}
	return time.Since(e.CreatedAt) > e.TTL
}
