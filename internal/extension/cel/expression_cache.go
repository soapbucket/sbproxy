// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"container/list"
	"crypto/md5"
	"encoding/hex"
	"sync"
	
	"github.com/google/cel-go/cel"
)

// ExpressionCache provides LRU caching for compiled CEL expressions
type ExpressionCache struct {
	mu       sync.RWMutex
	cache    map[string]*list.Element
	lruList  *list.List
	maxSize  int
	
	// Metrics
	hits     int64
	misses   int64
	evictions int64
}

type cacheEntry struct {
	key     string
	program cel.Program
	version string
}

// NewExpressionCache creates a new CEL expression cache
func NewExpressionCache(maxSize int) *ExpressionCache {
	if maxSize <= 0 {
		maxSize = 100 // Default size
	}
	
	return &ExpressionCache{
		cache:   make(map[string]*list.Element),
		lruList: list.New(),
		maxSize: maxSize,
	}
}

// Get retrieves a compiled expression from cache
func (ec *ExpressionCache) Get(expression string, version string) (cel.Program, bool) {
	ec.mu.RLock()
	
	key := ec.makeKey(expression, version)
	elem, found := ec.cache[key]
	
	if !found {
		ec.mu.RUnlock()
		ec.mu.Lock()
		ec.misses++
		ec.mu.Unlock()
		return nil, false
	}
	
	ec.mu.RUnlock()
	
	// Move to front (most recently used)
	ec.mu.Lock()
	ec.lruList.MoveToFront(elem)
	entry := elem.Value.(*cacheEntry)
	ec.hits++
	ec.mu.Unlock()
	
	return entry.program, true
}

// Put stores a compiled expression in cache
func (ec *ExpressionCache) Put(expression string, version string, program cel.Program) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	
	key := ec.makeKey(expression, version)
	
	// Check if already exists
	if elem, found := ec.cache[key]; found {
		ec.lruList.MoveToFront(elem)
		elem.Value.(*cacheEntry).program = program
		return
	}
	
	// Add new entry
	entry := &cacheEntry{
		key:     key,
		program: program,
		version: version,
	}
	
	elem := ec.lruList.PushFront(entry)
	ec.cache[key] = elem
	
	// Evict if over capacity
	if ec.lruList.Len() > ec.maxSize {
		ec.evictOldest()
	}
}

// evictOldest removes the least recently used entry
func (ec *ExpressionCache) evictOldest() {
	elem := ec.lruList.Back()
	if elem != nil {
		ec.lruList.Remove(elem)
		entry := elem.Value.(*cacheEntry)
		delete(ec.cache, entry.key)
		ec.evictions++
	}
}

// Clear removes all entries from cache
func (ec *ExpressionCache) Clear() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	
	ec.cache = make(map[string]*list.Element)
	ec.lruList = list.New()
}

// InvalidateVersion removes all entries for a specific version
func (ec *ExpressionCache) InvalidateVersion(version string) int {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	
	removed := 0
	for elem := ec.lruList.Front(); elem != nil; {
		entry := elem.Value.(*cacheEntry)
		next := elem.Next()
		
		if entry.version == version {
			ec.lruList.Remove(elem)
			delete(ec.cache, entry.key)
			removed++
		}
		
		elem = next
	}
	
	return removed
}

// Stats returns cache statistics
func (ec *ExpressionCache) Stats() ExpressionCacheStats {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	
	return ExpressionCacheStats{
		Size:      ec.lruList.Len(),
		Capacity:  ec.maxSize,
		Hits:      ec.hits,
		Misses:    ec.misses,
		Evictions: ec.evictions,
	}
}

// makeKey creates a cache key from expression and version
// Optimized: Use strings.Builder from pool to reduce allocations
func (ec *ExpressionCache) makeKey(expression string, version string) string {
	hash := md5.Sum([]byte(expression))
	
	// Estimate capacity: version length + 1 (colon) + 32 (hex hash)
	sb := cacher.GetBuilderWithSize(len(version) + 1 + 32)
	sb.WriteString(version)
	sb.WriteByte(':')
	sb.WriteString(hex.EncodeToString(hash[:]))
	result := sb.String()
	cacher.PutBuilder(sb)
	return result
}

// ExpressionCacheStats contains cache statistics
type ExpressionCacheStats struct {
	Size      int
	Capacity  int
	Hits      int64
	Misses    int64
	Evictions int64
}

// HitRate returns the cache hit rate percentage
func (s ExpressionCacheStats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0.0
	}
	return float64(s.Hits) / float64(total) * 100.0
}

// Utilization returns the cache utilization percentage
func (s ExpressionCacheStats) Utilization() float64 {
	if s.Capacity == 0 {
		return 0.0
	}
	return float64(s.Size) / float64(s.Capacity) * 100.0
}

