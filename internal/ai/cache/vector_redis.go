// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"bytes"
	"context"
	json "github.com/goccy/go-json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

const redisVectorStoreType = "ai_semantic_vectors"

// RedisVectorStore represents a redis vector store.
type RedisVectorStore struct {
	cacher  cacher.Cacher
	maxSize int
}

// NewRedisVectorStore creates and initializes a new RedisVectorStore.
func NewRedisVectorStore(c cacher.Cacher, maxSize int) *RedisVectorStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &RedisVectorStore{cacher: c, maxSize: maxSize}
}

// Search performs the search operation on the RedisVectorStore.
func (s *RedisVectorStore) Search(ctx context.Context, embedding []float32, threshold float64, limit int) ([]VectorEntry, error) {
	keys, err := s.cacher.ListKeys(ctx, s.cType(ctx), "")
	if err != nil {
		return nil, err
	}
	type scored struct {
		entry VectorEntry
		sim   float64
	}
	results := make([]scored, 0, len(keys))
	now := time.Now()
	for _, key := range keys {
		reader, err := s.cacher.Get(ctx, s.cType(ctx), key)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			continue
		}
		var entry VectorEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		if entry.IsExpired() {
			_ = s.cacher.Delete(ctx, s.cType(ctx), key)
			continue
		}
		entry.LastAccess = now
		sim := cosineSimilarity(embedding, entry.Embedding)
		if sim >= threshold {
			results = append(results, scored{entry: entry, sim: sim})
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].sim > results[j].sim })
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	out := make([]VectorEntry, len(results))
	for i, r := range results {
		out[i] = r.entry
		out[i].Similarity = r.sim
		_ = s.Store(ctx, r.entry)
	}
	return out, nil
}

// Store performs the store operation on the RedisVectorStore.
func (s *RedisVectorStore) Store(ctx context.Context, entry VectorEntry) error {
	entry.LastAccess = time.Now()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	ttl := entry.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if err := s.cacher.PutWithExpires(ctx, s.cType(ctx), entry.Key, bytes.NewReader(data), ttl); err != nil {
		return err
	}
	return s.pruneIfNeeded(ctx)
}

// Delete performs the delete operation on the RedisVectorStore.
func (s *RedisVectorStore) Delete(ctx context.Context, key string) error {
	return s.cacher.Delete(ctx, s.cType(ctx), key)
}

// Size performs the size operation on the RedisVectorStore.
func (s *RedisVectorStore) Size(ctx context.Context) (int64, error) {
	keys, err := s.cacher.ListKeys(ctx, s.cType(ctx), "")
	if err != nil {
		return 0, err
	}
	return int64(len(keys)), nil
}

func (s *RedisVectorStore) pruneIfNeeded(ctx context.Context) error {
	size, err := s.Size(ctx)
	if err != nil || size <= int64(s.maxSize) {
		return err
	}
	keys, err := s.cacher.ListKeys(ctx, s.cType(ctx), "")
	if err != nil {
		return err
	}
	type candidate struct {
		key  string
		last time.Time
	}
	candidates := make([]candidate, 0, len(keys))
	for _, key := range keys {
		reader, err := s.cacher.Get(ctx, s.cType(ctx), key)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			continue
		}
		var entry VectorEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		candidates = append(candidates, candidate{key: key, last: entry.LastAccess})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].last.Before(candidates[j].last) })
	for i := 0; i < len(candidates)-s.maxSize; i++ {
		_ = s.cacher.Delete(ctx, s.cType(ctx), candidates[i].key)
	}
	return nil
}

// Health returns the health status of the Redis vector store.
func (s *RedisVectorStore) Health(ctx context.Context) CacheHealth {
	size, err := s.Size(ctx)
	if err != nil {
		return CacheHealth{
			StoreType: "redis",
			Entries:   0,
			Capacity:  s.maxSize,
			Healthy:   false,
			Error:     err.Error(),
		}
	}
	return CacheHealth{
		StoreType: "redis",
		Entries:   size,
		Capacity:  s.maxSize,
		Healthy:   true,
	}
}

func (s *RedisVectorStore) cType(ctx context.Context) string {
	if rd := reqctx.GetRequestData(ctx); rd != nil && rd.Config != nil {
		if wid := reqctx.ConfigParams(rd.Config).GetWorkspaceID(); wid != "" {
			return fmt.Sprintf("%s:%s", redisVectorStoreType, wid)
		}
	}
	return redisVectorStoreType
}
