package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExactMatchCache_StoreAndLookup(t *testing.T) {
	store := NewMemoryExactStore()
	cache := NewExactMatchCache(ExactMatchConfig{Enabled: true}, store)
	ctx := context.Background()

	model := "gpt-4o"
	content := "What is the capital of France?"
	response := []byte(`{"answer":"Paris"}`)

	// Store
	cache.Store(ctx, model, content, response)

	// Lookup should hit
	got, ok := cache.Lookup(ctx, model, content)
	require.True(t, ok)
	assert.Equal(t, response, got)
}

func TestExactMatchCache_Miss(t *testing.T) {
	store := NewMemoryExactStore()
	cache := NewExactMatchCache(ExactMatchConfig{Enabled: true}, store)
	ctx := context.Background()

	got, ok := cache.Lookup(ctx, "gpt-4o", "unknown prompt")
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestExactMatchCache_DifferentModelsProduceDifferentKeys(t *testing.T) {
	store := NewMemoryExactStore()
	cache := NewExactMatchCache(ExactMatchConfig{Enabled: true}, store)
	ctx := context.Background()

	content := "What is 2+2?"
	resp1 := []byte(`{"model":"gpt-4o","answer":"4"}`)
	resp2 := []byte(`{"model":"claude","answer":"4"}`)

	cache.Store(ctx, "gpt-4o", content, resp1)
	cache.Store(ctx, "claude-3-opus", content, resp2)

	got1, ok1 := cache.Lookup(ctx, "gpt-4o", content)
	require.True(t, ok1)
	assert.Equal(t, resp1, got1)

	got2, ok2 := cache.Lookup(ctx, "claude-3-opus", content)
	require.True(t, ok2)
	assert.Equal(t, resp2, got2)
}

func TestExactMatchCache_NormalizesContent(t *testing.T) {
	store := NewMemoryExactStore()
	cache := NewExactMatchCache(ExactMatchConfig{Enabled: true}, store)
	ctx := context.Background()

	content := "  What is the Capital of France?  "
	response := []byte(`{"answer":"Paris"}`)

	cache.Store(ctx, "gpt-4o", content, response)

	// Same content with different casing/whitespace should hit
	got, ok := cache.Lookup(ctx, "gpt-4o", "What is the capital of France?")
	require.True(t, ok)
	assert.Equal(t, response, got)
}

func TestExactMatchCache_DisabledDoesNothing(t *testing.T) {
	store := NewMemoryExactStore()
	cache := NewExactMatchCache(ExactMatchConfig{Enabled: false}, store)
	ctx := context.Background()

	cache.Store(ctx, "gpt-4o", "test", []byte(`{"ok":true}`))

	got, ok := cache.Lookup(ctx, "gpt-4o", "test")
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestExactMatchCache_NilStore(t *testing.T) {
	cache := NewExactMatchCache(ExactMatchConfig{Enabled: true}, nil)
	ctx := context.Background()

	// Should not panic
	cache.Store(ctx, "gpt-4o", "test", []byte(`{"ok":true}`))
	got, ok := cache.Lookup(ctx, "gpt-4o", "test")
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestExactMatchCache_DefaultTTL(t *testing.T) {
	cache := NewExactMatchCache(ExactMatchConfig{Enabled: true}, NewMemoryExactStore())
	assert.Equal(t, time.Hour, cache.ttl)
}

func TestExactCacheKey_Deterministic(t *testing.T) {
	k1 := ExactCacheKeyForTest("gpt-4o", "hello world")
	k2 := ExactCacheKeyForTest("gpt-4o", "hello world")
	assert.Equal(t, k1, k2)
}

func TestExactCacheKey_DifferentModels(t *testing.T) {
	k1 := ExactCacheKeyForTest("gpt-4o", "hello")
	k2 := ExactCacheKeyForTest("claude-3-opus", "hello")
	assert.NotEqual(t, k1, k2)
}

func TestExactCacheKey_HasPrefix(t *testing.T) {
	key := ExactCacheKeyForTest("gpt-4o", "hello")
	assert.Contains(t, key, "exact:")
}

func TestNormalizeContent(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello World", "hello world"},
		{"  spaces  ", "spaces"},
		{"UPPER", "upper"},
		{"", ""},
		{"\n\ttabs\n", "tabs"},
	}

	for _, tt := range tests {
		got := NormalizeContentForTest(tt.input)
		assert.Equal(t, tt.expected, got, "input: %q", tt.input)
	}
}

func TestMemoryExactStore_Expiry(t *testing.T) {
	store := NewMemoryExactStore()
	ctx := context.Background()

	// Store with a very short TTL
	err := store.Set(ctx, "test-key", []byte("value"), time.Nanosecond)
	require.NoError(t, err)

	// Wait for expiry
	time.Sleep(time.Millisecond)

	got, err := store.Get(ctx, "test-key")
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestMemoryExactStore_NotFound(t *testing.T) {
	store := NewMemoryExactStore()
	ctx := context.Background()

	got, err := store.Get(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestMemoryExactStore_DefensiveCopy(t *testing.T) {
	store := NewMemoryExactStore()
	ctx := context.Background()

	original := []byte("original")
	err := store.Set(ctx, "key", original, time.Hour)
	require.NoError(t, err)

	// Mutate the original
	original[0] = 'X'

	// Stored value should be unchanged
	got, err := store.Get(ctx, "key")
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), got)
}

func TestMarshalUnmarshalResponse(t *testing.T) {
	type resp struct {
		Answer string `json:"answer"`
	}

	original := resp{Answer: "42"}
	data, err := MarshalResponse(original)
	require.NoError(t, err)

	var decoded resp
	err = UnmarshalResponse(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}
