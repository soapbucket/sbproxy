// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// SemanticCacheConfig configures the semantic cache.
type SemanticCacheConfig struct {
	Enabled             bool     `json:"enabled"`
	EmbeddingProvider   string   `json:"embedding_provider,omitempty"`
	EmbeddingModel      string   `json:"embedding_model,omitempty"`
	SimilarityThreshold float64  `json:"similarity_threshold,omitempty"`
	TTLSeconds          int      `json:"ttl_seconds,omitempty"`
	MaxEntries          int      `json:"max_entries,omitempty"`
	Store               string   `json:"store,omitempty"`
	ExcludeModels       []string `json:"exclude_models,omitempty"`
	CacheBy             []string `json:"cache_by,omitempty"`
	CrossProvider       bool     `json:"cross_provider,omitempty"`
	NormalizePrompts    bool     `json:"normalize_prompts,omitempty"`
	// Namespace controls cache key isolation to prevent cross-tenant leakage.
	// Options: "global" (no prefix), "per_workspace", "per_user", "per_key".
	// Default is empty, which derives the namespace from request context.
	Namespace string `json:"namespace,omitempty"`
}

// SemanticCache provides semantic similarity-based response caching.
type SemanticCache struct {
	store     VectorStore
	embedder  *Embedder
	config    *SemanticCacheConfig
	excludes  map[string]bool
}

// NewSemanticCache creates a new semantic cache.
func NewSemanticCache(cfg *SemanticCacheConfig, store VectorStore, embedFn EmbedFunc) *SemanticCache {
	if cfg.SimilarityThreshold <= 0 {
		cfg.SimilarityThreshold = 0.95
	}
	if cfg.TTLSeconds <= 0 {
		cfg.TTLSeconds = 3600
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}

	excludes := make(map[string]bool, len(cfg.ExcludeModels))
	for _, m := range cfg.ExcludeModels {
		excludes[m] = true
	}

	return &SemanticCache{
		store:    store,
		embedder: NewEmbedder(embedFn, 512),
		config:   cfg,
		excludes: excludes,
	}
}

// Lookup searches for a cached response matching the prompt.
func (sc *SemanticCache) Lookup(ctx context.Context, prompt, model string) ([]byte, bool, error) {
	if sc.excludes[model] {
		return nil, false, nil
	}
	namespace := sc.cacheNamespace(ctx)

	embedding, err := sc.embedder.Embed(ctx, prompt)
	if err != nil {
		return nil, false, nil // Fail open on embedding errors
	}

	results, err := sc.store.Search(ctx, embedding, sc.config.SimilarityThreshold, 1)
	if err != nil {
		return nil, false, nil // Fail open on search errors
	}

	if len(results) == 0 {
		return nil, false, nil
	}

	entry := results[0]
	if entry.Namespace != namespace {
		return nil, false, nil
	}
	if entry.IsExpired() {
		_ = sc.store.Delete(ctx, entry.Key)
		return nil, false, nil
	}

	// Decompress response
	response, err := decompress(entry.Response)
	if err != nil {
		return nil, false, nil
	}

	return response, true, nil
}

// LookupStale searches for a cached response, returning it even if expired.
// This is used for degraded-mode fallback when all providers are unavailable.
func (sc *SemanticCache) LookupStale(ctx context.Context, prompt, model string) ([]byte, bool, error) {
	if sc.excludes[model] {
		return nil, false, nil
	}
	namespace := sc.cacheNamespace(ctx)

	embedding, err := sc.embedder.Embed(ctx, prompt)
	if err != nil {
		return nil, false, nil // Fail open on embedding errors
	}

	results, err := sc.store.Search(ctx, embedding, sc.config.SimilarityThreshold, 1)
	if err != nil {
		return nil, false, nil // Fail open on search errors
	}

	if len(results) == 0 {
		return nil, false, nil
	}

	entry := results[0]
	if entry.Namespace != namespace {
		return nil, false, nil
	}

	// Unlike Lookup, do not reject expired entries - return them as stale
	response, err := decompress(entry.Response)
	if err != nil {
		return nil, false, nil
	}

	return response, true, nil
}

// Store caches a response with its prompt embedding.
func (sc *SemanticCache) Store(ctx context.Context, prompt, model string, response []byte) error {
	if sc.excludes[model] {
		return nil
	}
	namespace := sc.cacheNamespace(ctx)

	embedding, err := sc.embedder.Embed(ctx, prompt)
	if err != nil {
		return nil // Fail silently on embedding errors
	}

	compressed, err := compress(response)
	if err != nil {
		return nil
	}

	key := CacheKeyWithNamespace(namespace, prompt, model, sc.config.CrossProvider)
	entry := VectorEntry{
		Key:       key,
		Namespace: namespace,
		Embedding: embedding,
		Response:  compressed,
		Model:     model,
		CreatedAt: time.Now(),
		TTL:       time.Duration(sc.config.TTLSeconds) * time.Second,
	}

	return sc.store.Store(ctx, entry)
}

// IsExcluded returns true if the model is excluded from caching.
func (sc *SemanticCache) IsExcluded(model string) bool {
	return sc.excludes[model]
}

// Health returns the health status of the underlying cache store.
func (sc *SemanticCache) Health(ctx context.Context) CacheHealth {
	return sc.store.Health(ctx)
}

func (sc *SemanticCache) cacheNamespace(ctx context.Context) string {
	// If namespace is explicitly set to "global", no prefix is applied.
	if sc.config.Namespace == "global" {
		return ""
	}

	rd := reqctx.GetRequestData(ctx)
	if rd == nil {
		return ""
	}

	// If a specific namespace mode is configured, use it directly.
	switch sc.config.Namespace {
	case "per_workspace":
		if rd.Config != nil {
			if wid := reqctx.ConfigParams(rd.Config).GetWorkspaceID(); wid != "" {
				return "ws:" + wid
			}
		}
		return ""
	case "per_user":
		if rd.DebugHeaders != nil {
			if uid := rd.DebugHeaders["X-Sb-User-Id"]; uid != "" {
				return "user:" + uid
			}
		}
		return ""
	case "per_key":
		if rd.DebugHeaders != nil {
			if apiKey := rd.DebugHeaders["X-Sb-Api-Key-Id"]; apiKey != "" {
				return "key:" + apiKey
			}
		}
		return ""
	}

	// Default behavior: derive namespace from request context.
	parts := make([]string, 0, 3)
	if rd.Config != nil {
		if workspaceID := reqctx.ConfigParams(rd.Config).GetWorkspaceID(); workspaceID != "" {
			parts = append(parts, workspaceID)
		}
	}
	if rd.DebugHeaders != nil {
		if promptID := rd.DebugHeaders["X-Sb-Prompt-Id"]; promptID != "" {
			parts = append(parts, "prompt:"+promptID)
		}
		if promptEnv := rd.DebugHeaders["X-Sb-Prompt-Environment"]; promptEnv != "" {
			parts = append(parts, "env:"+promptEnv)
		}
	}
	if len(parts) > 0 {
		return joinCacheNamespace(parts)
	}
	return ""
}

func joinCacheNamespace(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "|" + p
	}
	return out
}

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
