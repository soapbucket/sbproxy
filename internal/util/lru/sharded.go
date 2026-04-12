// sharded.go provides a 16-way sharded LRU cache to reduce mutex contention.
package lru

import (
	"fmt"
	"hash/fnv"
)

const numShards = 16

// ShardedCache distributes keys across multiple Cache shards to reduce mutex
// contention under concurrent access. Each shard is an independent LRU cache
// with its own lock, so operations on different shards proceed in parallel.
type ShardedCache[K comparable, V any] struct {
	shards [numShards]*Cache[K, V]
}

// NewSharded creates a new ShardedCache with the given total capacity spread
// evenly across 16 shards. If onEvict is non-nil, it is called when an entry
// is evicted from any shard.
func NewSharded[K comparable, V any](totalSize int, onEvict EvictCallback[K, V]) *ShardedCache[K, V] {
	if totalSize <= 0 {
		totalSize = 128
	}
	perShard := totalSize / numShards
	if perShard < 1 {
		perShard = 1
	}

	sc := &ShardedCache[K, V]{}
	for i := 0; i < numShards; i++ {
		sc.shards[i] = New[K, V](perShard, onEvict)
	}
	return sc
}

// shard returns the Cache shard for the given key using FNV-1a hashing.
func (sc *ShardedCache[K, V]) shard(key K) *Cache[K, V] {
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "%v", key)
	return sc.shards[h.Sum32()%numShards]
}

// Get retrieves a value from the cache and marks it as recently used.
func (sc *ShardedCache[K, V]) Get(key K) (V, bool) {
	return sc.shard(key).Get(key)
}

// Put adds or updates a key-value pair. If the shard is full, its least
// recently used entry is evicted.
func (sc *ShardedCache[K, V]) Put(key K, value V) {
	sc.shard(key).Put(key, value)
}

// Delete removes a key from the cache. Returns true if the key was present.
func (sc *ShardedCache[K, V]) Delete(key K) bool {
	return sc.shard(key).Delete(key)
}

// Len returns the total number of entries across all shards.
func (sc *ShardedCache[K, V]) Len() int {
	total := 0
	for i := 0; i < numShards; i++ {
		total += sc.shards[i].Len()
	}
	return total
}

// Clear removes all entries from every shard without calling OnEvict.
func (sc *ShardedCache[K, V]) Clear() {
	for i := 0; i < numShards; i++ {
		sc.shards[i].Clear()
	}
}
