package cache

import (
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEmbedder returns a deterministic embedding based on text content.
func mockEmbedFn(_ context.Context, text string) ([]float32, error) {
	// Simple hash-like embedding for testing
	embedding := make([]float32, 8)
	for i, c := range text {
		embedding[i%8] += float32(c)
	}
	// Normalize
	var norm float32
	for _, v := range embedding {
		norm += v * v
	}
	if norm > 0 {
		for i := range embedding {
			embedding[i] /= norm
		}
	}
	return embedding, nil
}

func newTestCache(t *testing.T) *SemanticCache {
	t.Helper()
	store := NewMemoryVectorStore(100)
	cfg := &SemanticCacheConfig{
		Enabled:             true,
		SimilarityThreshold: 0.95,
		TTLSeconds:          3600,
		MaxEntries:          100,
	}
	return NewSemanticCache(cfg, store, mockEmbedFn)
}

func TestSemanticCache_StoreAndLookup(t *testing.T) {
	sc := newTestCache(t)
	ctx := context.Background()

	prompt := "What is the capital of France?"
	response := []byte(`{"answer": "Paris"}`)

	// Store
	err := sc.Store(ctx, prompt, "gpt-4o", response)
	require.NoError(t, err)

	// Lookup same prompt
	cached, hit, err := sc.Lookup(ctx, prompt, "gpt-4o")
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, response, cached)
}

func TestSemanticCache_Miss(t *testing.T) {
	sc := newTestCache(t)
	ctx := context.Background()

	// Store one prompt
	err := sc.Store(ctx, "What is 2+2?", "gpt-4o", []byte("4"))
	require.NoError(t, err)

	// Lookup completely different prompt
	_, hit, err := sc.Lookup(ctx, "Tell me a joke about elephants please right now", "gpt-4o")
	require.NoError(t, err)
	assert.False(t, hit)
}

func TestSemanticCache_ExcludedModel(t *testing.T) {
	store := NewMemoryVectorStore(100)
	cfg := &SemanticCacheConfig{
		Enabled:       true,
		TTLSeconds:    3600,
		ExcludeModels: []string{"gpt-4o-realtime"},
	}
	sc := NewSemanticCache(cfg, store, mockEmbedFn)
	ctx := context.Background()

	// Store with excluded model should be silently skipped
	err := sc.Store(ctx, "hello", "gpt-4o-realtime", []byte("hi"))
	require.NoError(t, err)

	// Lookup should miss
	_, hit, err := sc.Lookup(ctx, "hello", "gpt-4o-realtime")
	require.NoError(t, err)
	assert.False(t, hit)

	assert.True(t, sc.IsExcluded("gpt-4o-realtime"))
	assert.False(t, sc.IsExcluded("gpt-4o"))
}

func TestSemanticCache_TTLExpiry(t *testing.T) {
	store := NewMemoryVectorStore(100)
	cfg := &SemanticCacheConfig{
		Enabled:             true,
		SimilarityThreshold: 0.95,
		TTLSeconds:          1, // 1 second TTL
		MaxEntries:          100,
	}
	sc := NewSemanticCache(cfg, store, mockEmbedFn)
	ctx := context.Background()

	prompt := "What is 1+1?"
	err := sc.Store(ctx, prompt, "gpt-4o", []byte("2"))
	require.NoError(t, err)

	// Immediate lookup should hit
	_, hit, err := sc.Lookup(ctx, prompt, "gpt-4o")
	require.NoError(t, err)
	assert.True(t, hit)

	// Wait for TTL to expire
	time.Sleep(1100 * time.Millisecond)

	// Should miss after TTL
	_, hit, err = sc.Lookup(ctx, prompt, "gpt-4o")
	require.NoError(t, err)
	assert.False(t, hit)
}

func TestSemanticCache_CrossProvider(t *testing.T) {
	store := NewMemoryVectorStore(100)
	cfg := &SemanticCacheConfig{
		Enabled:             true,
		SimilarityThreshold: 0.95,
		TTLSeconds:          3600,
		CrossProvider:       true,
	}
	sc := NewSemanticCache(cfg, store, mockEmbedFn)
	ctx := context.Background()

	prompt := "What is the meaning of life?"
	response := []byte(`{"answer": "42"}`)

	// Store with GPT-4o
	err := sc.Store(ctx, prompt, "gpt-4o", response)
	require.NoError(t, err)

	// Lookup with different model should hit (cross-provider)
	cached, hit, err := sc.Lookup(ctx, prompt, "claude-3-5-sonnet", )
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, response, cached)
}

func TestSemanticCache_Compression(t *testing.T) {
	sc := newTestCache(t)
	ctx := context.Background()

	// Large response should compress
	response := make([]byte, 10000)
	for i := range response {
		response[i] = byte('a' + (i % 26))
	}

	err := sc.Store(ctx, "test prompt", "gpt-4o", response)
	require.NoError(t, err)

	cached, hit, err := sc.Lookup(ctx, "test prompt", "gpt-4o")
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, response, cached)
}

func TestSemanticCache_DefaultConfig(t *testing.T) {
	store := NewMemoryVectorStore(100)
	cfg := &SemanticCacheConfig{Enabled: true}
	sc := NewSemanticCache(cfg, store, mockEmbedFn)

	assert.Equal(t, 0.95, sc.config.SimilarityThreshold)
	assert.Equal(t, 3600, sc.config.TTLSeconds)
	assert.Equal(t, 10000, sc.config.MaxEntries)
}

func TestCacheKey(t *testing.T) {
	// Same prompt, same model should give same key
	k1 := CacheKey("hello", "gpt-4o", false)
	k2 := CacheKey("hello", "gpt-4o", false)
	assert.Equal(t, k1, k2)

	// Different model should give different key
	k3 := CacheKey("hello", "claude", false)
	assert.NotEqual(t, k1, k3)

	// Cross-provider mode should ignore model
	k4 := CacheKey("hello", "gpt-4o", true)
	k5 := CacheKey("hello", "claude", true)
	assert.Equal(t, k4, k5)

	k6 := CacheKeyWithNamespace("ws-1|prompt:abc", "hello", "gpt-4o", false)
	k7 := CacheKeyWithNamespace("ws-2|prompt:abc", "hello", "gpt-4o", false)
	assert.NotEqual(t, k6, k7)
}

func TestTruncateToTokens(t *testing.T) {
	short := "hello"
	assert.Equal(t, short, truncateToTokens(short, 100))

	// 512 tokens * 4 chars = 2048 chars
	long := string(make([]byte, 4000))
	truncated := truncateToTokens(long, 512)
	assert.Equal(t, 2048, len(truncated))
}

func TestExtractPromptText(t *testing.T) {
	messages := []map[string]interface{}{
		{"role": "system", "content": "You are helpful"},
		{"role": "user", "content": "Hello"},
		{"role": "assistant", "content": "Hi there"},
	}

	text := ExtractPromptText(messages)
	assert.NotContains(t, text, "You are helpful") // System excluded
	assert.Contains(t, text, "Hello")
	assert.Contains(t, text, "Hi there")
}

func TestSemanticCache_NamespaceSegregation(t *testing.T) {
	sc := newTestCache(t)
	rd1 := reqctx.NewRequestData()
	rd1.Config["workspace_id"] = "ws-1"
	rd1.AddDebugHeader("X-Sb-Prompt-Id", "prompt-a")
	ctx1 := reqctx.SetRequestData(context.Background(), rd1)

	rd2 := reqctx.NewRequestData()
	rd2.Config["workspace_id"] = "ws-2"
	rd2.AddDebugHeader("X-Sb-Prompt-Id", "prompt-a")
	ctx2 := reqctx.SetRequestData(context.Background(), rd2)

	err := sc.Store(ctx1, "hello", "gpt-4o", []byte("response-a"))
	require.NoError(t, err)

	cached, hit, err := sc.Lookup(ctx1, "hello", "gpt-4o")
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, []byte("response-a"), cached)

	_, hit, err = sc.Lookup(ctx2, "hello", "gpt-4o")
	require.NoError(t, err)
	assert.False(t, hit)
}
