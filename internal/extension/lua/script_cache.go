// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"container/list"
	"crypto/md5"
	"fmt"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

// ScriptCache provides LRU caching for compiled Lua scripts
type ScriptCache struct {
	mu      sync.RWMutex
	cache   map[string]*list.Element
	lruList *list.List
	maxSize int

	// Metrics
	hits      int64
	misses    int64
	evictions int64
}

type scriptCacheEntry struct {
	key      string
	function *lua.LFunction
	version  string
}

// NewScriptCache creates a new Lua script cache
func NewScriptCache(maxSize int) *ScriptCache {
	if maxSize <= 0 {
		maxSize = 50 // Default size (smaller than CEL as Lua is heavier)
	}

	return &ScriptCache{
		cache:   make(map[string]*list.Element),
		lruList: list.New(),
		maxSize: maxSize,
	}
}

// Get retrieves a compiled script from cache
func (sc *ScriptCache) Get(script string, version string) (*lua.LFunction, bool) {
	sc.mu.RLock()

	key := sc.makeKey(script, version)
	elem, found := sc.cache[key]

	if !found {
		sc.mu.RUnlock()
		sc.mu.Lock()
		sc.misses++
		sc.mu.Unlock()
		return nil, false
	}

	sc.mu.RUnlock()

	// Move to front (most recently used)
	sc.mu.Lock()
	sc.lruList.MoveToFront(elem)
	entry := elem.Value.(*scriptCacheEntry)
	sc.hits++
	sc.mu.Unlock()

	return entry.function, true
}

// Put stores a compiled script in cache
func (sc *ScriptCache) Put(script string, version string, function *lua.LFunction) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	key := sc.makeKey(script, version)

	// Check if already exists
	if elem, found := sc.cache[key]; found {
		sc.lruList.MoveToFront(elem)
		elem.Value.(*scriptCacheEntry).function = function
		return
	}

	// Add new entry
	entry := &scriptCacheEntry{
		key:      key,
		function: function,
		version:  version,
	}

	elem := sc.lruList.PushFront(entry)
	sc.cache[key] = elem

	// Evict if over capacity
	if sc.lruList.Len() > sc.maxSize {
		sc.evictOldest()
	}
}

// evictOldest removes the least recently used entry
func (sc *ScriptCache) evictOldest() {
	elem := sc.lruList.Back()
	if elem != nil {
		sc.lruList.Remove(elem)
		entry := elem.Value.(*scriptCacheEntry)
		delete(sc.cache, entry.key)
		sc.evictions++
	}
}

// Clear removes all entries from cache
func (sc *ScriptCache) Clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.cache = make(map[string]*list.Element)
	sc.lruList = list.New()
}

// InvalidateVersion removes all entries for a specific version
func (sc *ScriptCache) InvalidateVersion(version string) int {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	removed := 0
	for elem := sc.lruList.Front(); elem != nil; {
		entry := elem.Value.(*scriptCacheEntry)
		next := elem.Next()

		if entry.version == version {
			sc.lruList.Remove(elem)
			delete(sc.cache, entry.key)
			removed++
		}

		elem = next
	}

	return removed
}

// Stats returns cache statistics
func (sc *ScriptCache) Stats() ScriptCacheStats {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return ScriptCacheStats{
		Size:      sc.lruList.Len(),
		Capacity:  sc.maxSize,
		Hits:      sc.hits,
		Misses:    sc.misses,
		Evictions: sc.evictions,
	}
}

// makeKey creates a cache key from script and version
func (sc *ScriptCache) makeKey(script string, version string) string {
	hash := md5.Sum([]byte(script))
	return fmt.Sprintf("%s:%x", version, hash)
}

// ScriptCacheStats contains cache statistics
type ScriptCacheStats struct {
	Size      int
	Capacity  int
	Hits      int64
	Misses    int64
	Evictions int64
}

// HitRate returns the cache hit rate percentage
func (s ScriptCacheStats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0.0
	}
	return float64(s.Hits) / float64(total) * 100.0
}

// Utilization returns the cache utilization percentage
func (s ScriptCacheStats) Utilization() float64 {
	if s.Capacity == 0 {
		return 0.0
	}
	return float64(s.Size) / float64(s.Capacity) * 100.0
}
