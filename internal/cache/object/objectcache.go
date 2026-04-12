// Package objectcache implements an in-memory object cache with TTL expiration and size limits.
package objectcache

import (
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultExpireInterval    = 10 * time.Minute
	defaultCleanupInterval   = 1 * time.Minute
	smallCacheExactLRUCutoff = 32
	hitPromotionInterval     = 16
)

var (
	nullTime = time.Time{}

	// Pools for reusing objects
	entryPool = sync.Pool{
		New: func() interface{} {
			return &entry{}
		},
	}

	nodePool = sync.Pool{
		New: func() interface{} {
			return &lruNode{}
		},
	}

	// Pool for node slices used in bulk operations
	nodeSlicePool = sync.Pool{
		New: func() interface{} {
			s := make([]*lruNode, 0, 256)
			return &s
		},
	}
)

type entry struct {
	value   interface{}
	expires time.Time
	size    int64
}

// IsExpired reports whether the entry is expired.
func (e *entry) IsExpired() bool {
	return e.expires != nullTime && e.expires.Before(time.Now())
}

// lruNode represents a node in the LRU doubly linked list
type lruNode struct {
	key   string
	entry *entry
	prev  *lruNode
	next  *lruNode
}

// ObjectCache represents a object cache.
type ObjectCache struct {
	connections   map[string]*lruNode
	mu            sync.RWMutex
	exp           time.Duration
	interval      time.Duration
	maxObjects    int
	maxMemory     int64
	currentMemory int64

	// LRU list head and tail
	head *lruNode
	tail *lruNode

	close  chan struct{}
	done   chan struct{}
	closed bool

	getCounter atomic.Uint64
}

// Get retrieves a value from the ObjectCache.
func (c *ObjectCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	node, ok := c.connections[key]
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}

	if node.entry.IsExpired() {
		c.mu.RUnlock()
		c.mu.Lock()
		// Double-check after acquiring write lock
		if node, ok := c.connections[key]; ok && node.entry.IsExpired() {
			c.removeNode(node)
			c.currentMemory -= node.entry.size
			delete(c.connections, key)
			c.returnToPool(node)
		}
		c.mu.Unlock()
		return nil, false
	}

	// Capture value while still holding read lock to prevent race with
	// cleaner's returnToPool which sets node.entry = nil.
	value := node.entry.value
	cacheSize := len(c.connections)
	c.mu.RUnlock()

	if c.shouldPromoteHit(cacheSize) {
		// Move to front of LRU list, re-validating after acquiring write lock
		c.mu.Lock()
		if currentNode, ok := c.connections[key]; ok && currentNode == node {
			c.moveToFront(node)
		}
		c.mu.Unlock()
	}
	return value, true
}

func (c *ObjectCache) shouldPromoteHit(cacheSize int) bool {
	if cacheSize <= smallCacheExactLRUCutoff {
		return true
	}
	return c.getCounter.Add(1)%hitPromotionInterval == 0
}

// PutWithExpires performs the put with expires operation on the ObjectCache.
func (c *ObjectCache) PutWithExpires(key string, value interface{}, d time.Duration) {
	// Calculate entry size
	var size int64
	switch v := value.(type) {
	case []byte:
		size = int64(len(v))
	case string:
		size = int64(len(v))
	case int64, int, int32, int16, int8:
		size = 8 // Approximate size for integers
	case float64, float32:
		size = 8 // Approximate size for floats
	default:
		size = 64 // Default size for other types
	}

	// Get entry from pool
	e := entryPool.Get().(*entry)
	e.value = value
	e.size = size
	if d != 0 {
		e.expires = time.Now().Add(d)
	} else {
		e.expires = nullTime
	}

	c.mu.Lock()

	// Remove existing entry if it exists
	if existingNode, exists := c.connections[key]; exists {
		c.removeNode(existingNode)
		c.currentMemory -= existingNode.entry.size
		// Return old objects to pool
		c.returnToPool(existingNode)
	}

	// Check if we need to evict entries
	c.evictIfNeeded(size)

	// Get node from pool
	node := nodePool.Get().(*lruNode)
	node.key = key
	node.entry = e
	node.prev = nil
	node.next = nil

	c.addToFront(node)
	c.connections[key] = node
	c.currentMemory += size

	c.mu.Unlock()
}

// Put performs the put operation on the ObjectCache.
func (c *ObjectCache) Put(key string, value interface{}) {
	c.PutWithExpires(key, value, c.exp)
}

// Delete performs the delete operation on the ObjectCache.
func (c *ObjectCache) Delete(key string) {
	c.mu.Lock()
	if node, exists := c.connections[key]; exists {
		c.removeNode(node)
		c.currentMemory -= node.entry.size
		delete(c.connections, key)
		c.returnToPool(node)
	}
	c.mu.Unlock()
}

// returnToPool returns node and entry back to their respective pools
func (c *ObjectCache) returnToPool(node *lruNode) {
	if node.entry != nil {
		node.entry.value = nil // Clear reference
		entryPool.Put(node.entry)
		node.entry = nil
	}
	node.key = ""
	node.prev = nil
	node.next = nil
	nodePool.Put(node)
}

// GetKeys returns the keys for the ObjectCache.
func (c *ObjectCache) GetKeys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.connections))
	for key := range c.connections {
		keys = append(keys, key)
	}
	return keys
}

// GetKeysByPrefix returns the keys by prefix for the ObjectCache.
func (c *ObjectCache) GetKeysByPrefix(prefix string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.connections)/4) // Heuristic: assume ~25% match
	for key := range c.connections {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys
}

// DeleteByPrefix performs the delete by prefix operation on the ObjectCache.
func (c *ObjectCache) DeleteByPrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get slice from pool
	nodesToDeletePtr := nodeSlicePool.Get().(*[]*lruNode)
	nodesToDelete := (*nodesToDeletePtr)[:0] // Reset length, keep capacity

	// Collect nodes to delete while holding the lock
	for k, node := range c.connections {
		if strings.HasPrefix(k, prefix) {
			nodesToDelete = append(nodesToDelete, node)
		}
	}

	// Delete all matching nodes
	for _, node := range nodesToDelete {
		c.removeNode(node)
		c.currentMemory -= node.entry.size
		delete(c.connections, node.key)
		c.returnToPool(node)
	}

	// Clear references and return to pool
	for i := range nodesToDelete {
		nodesToDelete[i] = nil
	}
	*nodesToDeletePtr = nodesToDelete
	nodeSlicePool.Put(nodesToDeletePtr)
}

func (c *ObjectCache) cleaner() {
	slog.Debug("cleaner started")
	defer close(c.done)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.close:
			slog.Debug("exiting cleaner")
			return
		case <-ticker.C:
		}
		slog.Debug("running cleaner")

		// Get slice from pool
		expiredNodesPtr := nodeSlicePool.Get().(*[]*lruNode)
		expiredNodes := (*expiredNodesPtr)[:0] // Reset length, keep capacity

		// Collect expired nodes in a single pass
		c.mu.RLock()
		for _, node := range c.connections {
			if node.entry.IsExpired() {
				expiredNodes = append(expiredNodes, node)
			}
		}
		c.mu.RUnlock()

		if len(expiredNodes) > 0 {
			c.mu.Lock()
			for _, node := range expiredNodes {
				// Verify node still exists and is still expired (double-check pattern)
				if existingNode, exists := c.connections[node.key]; exists && existingNode == node && node.entry.IsExpired() {
					// close the connection and then remove...
					if closer, ok := node.entry.value.(io.Closer); ok {
						if err := closer.Close(); err != nil {
							slog.Error("error closing connection", "error", err)
						}
					}
					c.removeNode(node)
					c.currentMemory -= node.entry.size
					delete(c.connections, node.key)
					c.returnToPool(node)
				}
			}
			c.mu.Unlock()
		}

		// Clear references and return to pool
		for i := range expiredNodes {
			expiredNodes[i] = nil
		}
		*expiredNodesPtr = expiredNodes
		nodeSlicePool.Put(expiredNodesPtr)
	}
}

// Close releases resources held by the ObjectCache.
func (c *ObjectCache) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	// Signal the cleaner to stop
	close(c.close)

	// Wait for the cleaner to complete
	<-c.done

	// Now safely close all connections
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, node := range c.connections {
		if closer, ok := node.entry.value.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				slog.Error("error closing connection", "error", err)
			}
		}
		c.returnToPool(node)
	}

	// Clear the connections map
	c.connections = make(map[string]*lruNode)
	c.currentMemory = 0
	c.head = nil
	c.tail = nil

	return nil
}

// NewObjectCache creates and initializes a new ObjectCache.
func NewObjectCache(expire, cleanupInterval time.Duration, maxObjects int, maxMemory int64) (*ObjectCache, error) {
	if expire == 0 {
		return nil, ErrInvalidDuration
	} else if expire < 0 {
		expire = defaultExpireInterval
	}
	if cleanupInterval == 0 {
		return nil, ErrInvalidInterval
	} else if cleanupInterval < 0 {
		cleanupInterval = defaultCleanupInterval
	}

	m := &ObjectCache{
		connections:   make(map[string]*lruNode),
		close:         make(chan struct{}),
		done:          make(chan struct{}),
		exp:           expire,
		interval:      cleanupInterval,
		maxObjects:    maxObjects,
		maxMemory:     maxMemory,
		currentMemory: 0,
	}

	if m.interval > 0 {
		go m.cleaner()
	}
	return m, nil
}

// Increment atomically increments a counter stored at key by count.
// If the key does not exist, it is initialized to 0 before incrementing.
// Returns the new value.
func (c *ObjectCache) Increment(key string, count int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	var currentValue int64
	if node, ok := c.connections[key]; ok && !node.entry.IsExpired() {
		switch v := node.entry.value.(type) {
		case int64:
			currentValue = v
		case int:
			currentValue = int64(v)
		}
	}

	newValue := currentValue + count
	// Reuse PutWithExpires logic but under the same lock hold
	e := entryPool.Get().(*entry)
	e.value = newValue
	e.size = 8
	e.expires = time.Now().Add(c.exp)

	if existingNode, exists := c.connections[key]; exists {
		c.removeNode(existingNode)
		c.currentMemory -= existingNode.entry.size
		c.returnToPool(existingNode)
	}

	c.evictIfNeeded(8)

	node := nodePool.Get().(*lruNode)
	node.key = key
	node.entry = e
	node.prev = nil
	node.next = nil

	c.addToFront(node)
	c.connections[key] = node
	c.currentMemory += 8

	return newValue
}

// IncrementWithExpires atomically increments a counter and sets its TTL.
func (c *ObjectCache) IncrementWithExpires(key string, count int64, d time.Duration) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	var currentValue int64
	if node, ok := c.connections[key]; ok && !node.entry.IsExpired() {
		switch v := node.entry.value.(type) {
		case int64:
			currentValue = v
		case int:
			currentValue = int64(v)
		}
	}

	newValue := currentValue + count
	e := entryPool.Get().(*entry)
	e.value = newValue
	e.size = 8
	if d != 0 {
		e.expires = time.Now().Add(d)
	} else {
		e.expires = nullTime
	}

	if existingNode, exists := c.connections[key]; exists {
		c.removeNode(existingNode)
		c.currentMemory -= existingNode.entry.size
		c.returnToPool(existingNode)
	}

	c.evictIfNeeded(8)

	node := nodePool.Get().(*lruNode)
	node.key = key
	node.entry = e
	node.prev = nil
	node.next = nil

	c.addToFront(node)
	c.connections[key] = node
	c.currentMemory += 8

	return newValue
}

// LRU helper methods

// addToFront adds a node to the front of the LRU list
func (c *ObjectCache) addToFront(node *lruNode) {
	if c.head == nil {
		c.head = node
		c.tail = node
		return
	}

	node.next = c.head
	c.head.prev = node
	c.head = node
}

// removeNode removes a node from the LRU list
func (c *ObjectCache) removeNode(node *lruNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		c.head = node.next
	}

	if node.next != nil {
		node.next.prev = node.prev
	} else {
		c.tail = node.prev
	}
}

// moveToFront moves an existing node to the front of the LRU list
func (c *ObjectCache) moveToFront(node *lruNode) {
	if node == c.head {
		return
	}

	c.removeNode(node)
	c.addToFront(node)
}

// evictIfNeeded evicts LRU entries if limits are exceeded
func (c *ObjectCache) evictIfNeeded(newEntrySize int64) {
	// Check object count limit
	if c.maxObjects > 0 && len(c.connections) >= c.maxObjects {
		// Evict least recently used entry
		if c.tail != nil {
			nodeToEvict := c.tail
			c.removeNode(nodeToEvict)
			c.currentMemory -= nodeToEvict.entry.size
			delete(c.connections, nodeToEvict.key)
			c.returnToPool(nodeToEvict)
		}
	}

	// Check memory limit
	if c.maxMemory > 0 && c.currentMemory+newEntrySize > c.maxMemory {
		// Evict entries until we have enough space
		for c.tail != nil && c.currentMemory+newEntrySize > c.maxMemory {
			nodeToEvict := c.tail
			c.removeNode(nodeToEvict)
			c.currentMemory -= nodeToEvict.entry.size
			delete(c.connections, nodeToEvict.key)
			c.returnToPool(nodeToEvict)
		}
	}
}
