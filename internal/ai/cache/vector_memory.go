// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"context"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"
)

// MemoryVectorStore is an in-memory vector store with brute-force cosine similarity.
type MemoryVectorStore struct {
	entries map[string]*VectorEntry
	maxSize int
	mu      sync.RWMutex
}

// NewMemoryVectorStore creates a new in-memory vector store.
func NewMemoryVectorStore(maxSize int) *MemoryVectorStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &MemoryVectorStore{
		entries: make(map[string]*VectorEntry),
		maxSize: maxSize,
	}
}

// Search performs the search operation on the MemoryVectorStore.
func (s *MemoryVectorStore) Search(_ context.Context, embedding []float32, threshold float64, limit int) ([]VectorEntry, error) {
	s.mu.RLock()

	type scored struct {
		key        string
		entry      VectorEntry
		similarity float64
	}

	var results []scored
	for key, e := range s.entries {
		if e.IsExpired() {
			continue
		}
		sim := cosineSimilarity(embedding, e.Embedding)
		if sim >= threshold {
			results = append(results, scored{key: key, entry: *e, similarity: sim})
		}
	}
	s.mu.RUnlock()

	// Sort by similarity descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].similarity > results[j].similarity
	})

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	entries := make([]VectorEntry, len(results))
	for i, r := range results {
		entries[i] = r.entry
		entries[i].Similarity = r.similarity
	}

	if len(results) > 0 {
		now := time.Now()
		s.mu.Lock()
		for _, r := range results {
			if existing, ok := s.entries[r.key]; ok {
				existing.LastAccess = now
			}
		}
		s.mu.Unlock()
	}
	return entries, nil
}

// Store performs the store operation on the MemoryVectorStore.
func (s *MemoryVectorStore) Store(_ context.Context, entry VectorEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict expired entries if at capacity
	if len(s.entries) >= s.maxSize {
		s.evictExpired()
	}

	// If still at capacity, evict LRU (least recently used) entry
	if len(s.entries) >= s.maxSize {
		s.evictLRU()
	}

	e := entry
	e.LastAccess = time.Now()
	s.entries[entry.Key] = &e
	return nil
}

// Delete performs the delete operation on the MemoryVectorStore.
func (s *MemoryVectorStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
	return nil
}

// Size performs the size operation on the MemoryVectorStore.
func (s *MemoryVectorStore) Size(_ context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.entries)), nil
}

// Health returns the health status of the in-memory vector store.
func (s *MemoryVectorStore) Health(_ context.Context) CacheHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return CacheHealth{
		StoreType: "memory",
		Entries:   int64(len(s.entries)),
		Capacity:  s.maxSize,
		Healthy:   true,
	}
}

func (s *MemoryVectorStore) evictExpired() {
	for key, e := range s.entries {
		if e.IsExpired() {
			delete(s.entries, key)
		}
	}
}

func (s *MemoryVectorStore) evictLRU() {
	var lruKey string
	var lruTime time.Time

	// Find the least recently used entry (oldest last access)
	for key, e := range s.entries {
		if lruTime.IsZero() || e.LastAccess.Before(lruTime) {
			lruTime = e.LastAccess
			lruKey = key
		}
	}

	if lruKey != "" {
		delete(s.entries, lruKey)
		slog.Debug("semantic cache LRU eviction", "key", lruKey, "last_access", lruTime)
	}
}

// cosineSimilarity computes the cosine similarity between two vectors.
func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}
