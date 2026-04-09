package cache

import (
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRedisBackedTestStore(t *testing.T) *RedisVectorStore {
	t.Helper()
	mem, err := cacher.NewMemoryCacher(cacher.Settings{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mem.Close() })
	return NewRedisVectorStore(mem, 100)
}

func TestRedisVectorStore_StoreAndSearch(t *testing.T) {
	store := newRedisBackedTestStore(t)
	ctx := context.Background()

	entry := VectorEntry{
		Key:       "redis-test-1",
		Embedding: []float32{1, 0, 0},
		Response:  []byte("response"),
		Model:     "gpt-4o",
		CreatedAt: time.Now(),
		TTL:       time.Hour,
	}
	require.NoError(t, store.Store(ctx, entry))

	results, err := store.Search(ctx, []float32{1, 0, 0}, 0.9, 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "redis-test-1", results[0].Key)
}

func TestRedisVectorStore_Delete(t *testing.T) {
	store := newRedisBackedTestStore(t)
	ctx := context.Background()
	require.NoError(t, store.Store(ctx, VectorEntry{
		Key:       "delete-me",
		Embedding: []float32{1, 0},
		Response:  []byte("x"),
		CreatedAt: time.Now(),
		TTL:       time.Hour,
	}))
	require.NoError(t, store.Delete(ctx, "delete-me"))
	results, err := store.Search(ctx, []float32{1, 0}, 0.9, 10)
	require.NoError(t, err)
	assert.Len(t, results, 0)
}
