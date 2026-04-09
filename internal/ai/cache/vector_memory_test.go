package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryVectorStore_StoreAndSearch(t *testing.T) {
	store := NewMemoryVectorStore(100)
	ctx := context.Background()

	entry := VectorEntry{
		Key:       "test-1",
		Embedding: []float32{1, 0, 0},
		Response:  []byte("response"),
		Model:     "gpt-4o",
		CreatedAt: time.Now(),
		TTL:       time.Hour,
	}
	require.NoError(t, store.Store(ctx, entry))

	// Search with same embedding should find it
	results, err := store.Search(ctx, []float32{1, 0, 0}, 0.9, 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "test-1", results[0].Key)
	assert.InDelta(t, 1.0, results[0].Similarity, 0.001)
}

func TestMemoryVectorStore_SearchThreshold(t *testing.T) {
	store := NewMemoryVectorStore(100)
	ctx := context.Background()

	require.NoError(t, store.Store(ctx, VectorEntry{
		Key: "a", Embedding: []float32{1, 0, 0}, Response: []byte("a"),
		CreatedAt: time.Now(), TTL: time.Hour,
	}))
	require.NoError(t, store.Store(ctx, VectorEntry{
		Key: "b", Embedding: []float32{0, 1, 0}, Response: []byte("b"),
		CreatedAt: time.Now(), TTL: time.Hour,
	}))

	// Searching with [1,0,0] should find "a" but not "b" at high threshold
	results, err := store.Search(ctx, []float32{1, 0, 0}, 0.9, 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "a", results[0].Key)
}

func TestMemoryVectorStore_SearchSorted(t *testing.T) {
	store := NewMemoryVectorStore(100)
	ctx := context.Background()

	require.NoError(t, store.Store(ctx, VectorEntry{
		Key: "close", Embedding: []float32{0.9, 0.1, 0}, Response: []byte("close"),
		CreatedAt: time.Now(), TTL: time.Hour,
	}))
	require.NoError(t, store.Store(ctx, VectorEntry{
		Key: "exact", Embedding: []float32{1, 0, 0}, Response: []byte("exact"),
		CreatedAt: time.Now(), TTL: time.Hour,
	}))

	results, err := store.Search(ctx, []float32{1, 0, 0}, 0.5, 10)
	require.NoError(t, err)
	require.Len(t, results, 2)
	// Exact match should be first
	assert.Equal(t, "exact", results[0].Key)
}

func TestMemoryVectorStore_SearchLimit(t *testing.T) {
	store := NewMemoryVectorStore(100)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, store.Store(ctx, VectorEntry{
			Key: string(rune('a' + i)), Embedding: []float32{1, 0, 0},
			Response: []byte("x"), CreatedAt: time.Now(), TTL: time.Hour,
		}))
	}

	results, err := store.Search(ctx, []float32{1, 0, 0}, 0.9, 2)
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestMemoryVectorStore_Delete(t *testing.T) {
	store := NewMemoryVectorStore(100)
	ctx := context.Background()

	require.NoError(t, store.Store(ctx, VectorEntry{
		Key: "del", Embedding: []float32{1, 0, 0}, Response: []byte("x"),
		CreatedAt: time.Now(), TTL: time.Hour,
	}))

	size, _ := store.Size(ctx)
	assert.Equal(t, int64(1), size)

	require.NoError(t, store.Delete(ctx, "del"))

	size, _ = store.Size(ctx)
	assert.Equal(t, int64(0), size)
}

func TestMemoryVectorStore_Size(t *testing.T) {
	store := NewMemoryVectorStore(100)
	ctx := context.Background()

	size, err := store.Size(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), size)

	require.NoError(t, store.Store(ctx, VectorEntry{
		Key: "a", Embedding: []float32{1}, Response: []byte("x"),
		CreatedAt: time.Now(), TTL: time.Hour,
	}))

	size, _ = store.Size(ctx)
	assert.Equal(t, int64(1), size)
}

func TestMemoryVectorStore_ExpiredEntries(t *testing.T) {
	store := NewMemoryVectorStore(100)
	ctx := context.Background()

	require.NoError(t, store.Store(ctx, VectorEntry{
		Key: "expired", Embedding: []float32{1, 0, 0}, Response: []byte("x"),
		CreatedAt: time.Now().Add(-2 * time.Hour), TTL: time.Hour,
	}))

	// Should not find expired entry
	results, err := store.Search(ctx, []float32{1, 0, 0}, 0.9, 10)
	require.NoError(t, err)
	assert.Len(t, results, 0)
}

func TestMemoryVectorStore_MaxSize(t *testing.T) {
	store := NewMemoryVectorStore(3)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, store.Store(ctx, VectorEntry{
			Key: string(rune('a' + i)), Embedding: []float32{float32(i)},
			Response: []byte("x"), CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
			TTL: time.Hour,
		}))
	}

	size, _ := store.Size(ctx)
	assert.LessOrEqual(t, size, int64(3))
}

func TestCosineSimilarity(t *testing.T) {
	tests := []struct {
		a, b     []float32
		expected float64
	}{
		{[]float32{1, 0, 0}, []float32{1, 0, 0}, 1.0},
		{[]float32{1, 0, 0}, []float32{0, 1, 0}, 0.0},
		{[]float32{1, 0, 0}, []float32{-1, 0, 0}, -1.0},
		{[]float32{1, 1}, []float32{1, 1}, 1.0},
		{[]float32{}, []float32{}, 0.0},
		{[]float32{1}, []float32{1, 2}, 0.0}, // different lengths
	}

	for _, tt := range tests {
		sim := cosineSimilarity(tt.a, tt.b)
		assert.InDelta(t, tt.expected, sim, 0.001)
	}
}

func TestMemoryVectorStore_Concurrent(t *testing.T) {
	store := NewMemoryVectorStore(1000)
	ctx := context.Background()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				entry := VectorEntry{
					Key: string(rune(id*100 + j)), Embedding: []float32{float32(id), float32(j)},
					Response: []byte("x"), CreatedAt: time.Now(), TTL: time.Hour,
				}
				_ = store.Store(ctx, entry)
				_, _ = store.Search(ctx, []float32{float32(id), float32(j)}, 0.5, 5)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	size, _ := store.Size(ctx)
	assert.Greater(t, size, int64(0))
}
