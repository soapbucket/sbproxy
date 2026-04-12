// Package lru provides a generic O(1) LRU cache using a doubly-linked list and hash map.
package lru

import "sync"

// EvictCallback is called when an entry is evicted from the cache.
type EvictCallback[K comparable, V any] func(key K, value V)

// entry is a node in the doubly-linked list.
type entry[K comparable, V any] struct {
	key   K
	value V
	prev  *entry[K, V]
	next  *entry[K, V]
}

// Cache is a thread-safe LRU cache with O(1) get, put, and eviction.
type Cache[K comparable, V any] struct {
	mu      sync.Mutex
	maxSize int
	items   map[K]*entry[K, V]
	head    *entry[K, V] // most recently used
	tail    *entry[K, V] // least recently used
	onEvict EvictCallback[K, V]
}

// New creates a new LRU cache with the given maximum size.
// If onEvict is non-nil, it is called when an entry is evicted.
func New[K comparable, V any](maxSize int, onEvict EvictCallback[K, V]) *Cache[K, V] {
	if maxSize <= 0 {
		maxSize = 128
	}
	return &Cache[K, V]{
		maxSize: maxSize,
		items:   make(map[K]*entry[K, V], maxSize),
		onEvict: onEvict,
	}
}

// Get retrieves a value from the cache and marks it as recently used.
// Returns the value and true if found, or the zero value and false otherwise.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}

	c.moveToFront(e)
	return e.value, true
}

// Put adds or updates a key-value pair. If the cache is full, the least
// recently used entry is evicted.
func (c *Cache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.items[key]; ok {
		e.value = value
		c.moveToFront(e)
		return
	}

	e := &entry[K, V]{key: key, value: value}
	c.items[key] = e
	c.pushFront(e)

	if len(c.items) > c.maxSize {
		c.evictLRU()
	}
}

// Delete removes a key from the cache. Returns true if the key was present.
func (c *Cache[K, V]) Delete(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.items[key]
	if !ok {
		return false
	}

	c.removeEntry(e)
	delete(c.items, key)
	return true
}

// Len returns the number of entries in the cache.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// Clear removes all entries from the cache without calling OnEvict.
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[K]*entry[K, V], c.maxSize)
	c.head = nil
	c.tail = nil
}

// moveToFront moves an existing entry to the front (MRU position).
func (c *Cache[K, V]) moveToFront(e *entry[K, V]) {
	if c.head == e {
		return
	}
	c.removeEntry(e)
	c.pushFront(e)
}

// pushFront inserts an entry at the front of the list.
func (c *Cache[K, V]) pushFront(e *entry[K, V]) {
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
}

// removeEntry unlinks an entry from the list.
func (c *Cache[K, V]) removeEntry(e *entry[K, V]) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}

// evictLRU removes the least recently used entry.
func (c *Cache[K, V]) evictLRU() {
	if c.tail == nil {
		return
	}
	e := c.tail
	c.removeEntry(e)
	delete(c.items, e.key)
	if c.onEvict != nil {
		c.onEvict(e.key, e.value)
	}
}
