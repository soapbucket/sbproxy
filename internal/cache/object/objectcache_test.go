package objectcache

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockCloser is a mock type that implements io.Closer
type mockCloser struct {
	closed bool
	mu     sync.Mutex
}

func (m *mockCloser) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockCloser) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// TestNewObjectCache tests the constructor
func TestNewObjectCache(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		expire          time.Duration
		cleanupInterval time.Duration
		maxObjects      int
		maxMemory       int64
		wantErr         bool
	}{
		{
			name:            "valid parameters",
			expire:          5 * time.Minute,
			cleanupInterval: 1 * time.Minute,
			maxObjects:      100,
			maxMemory:       1024 * 1024,
			wantErr:         false,
		},
		{
			name:            "zero expire",
			expire:          0,
			cleanupInterval: 1 * time.Minute,
			maxObjects:      100,
			maxMemory:       1024,
			wantErr:         true,
		},
		{
			name:            "zero cleanup interval",
			expire:          5 * time.Minute,
			cleanupInterval: 0,
			maxObjects:      100,
			maxMemory:       1024,
			wantErr:         true,
		},
		{
			name:            "negative expire uses default",
			expire:          -1,
			cleanupInterval: 1 * time.Minute,
			maxObjects:      100,
			maxMemory:       1024,
			wantErr:         false,
		},
		{
			name:            "negative cleanup interval uses default",
			expire:          5 * time.Minute,
			cleanupInterval: -1,
			maxObjects:      100,
			maxMemory:       1024,
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := NewObjectCache(tt.expire, tt.cleanupInterval, tt.maxObjects, tt.maxMemory)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewObjectCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && cache == nil {
				t.Error("NewObjectCache() returned nil cache")
			}
			if cache != nil {
				cache.Close()
			}
		})
	}
}

// TestPutAndGet tests basic put and get operations
func TestPutAndGet(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Test string value
	cache.Put("key1", "value1")
	val, ok := cache.Get("key1")
	if !ok {
		t.Error("Expected to find key1")
	}
	if val != "value1" {
		t.Errorf("Expected value1, got %v", val)
	}

	// Test byte slice value
	cache.Put("key2", []byte("value2"))
	val, ok = cache.Get("key2")
	if !ok {
		t.Error("Expected to find key2")
	}
	if string(val.([]byte)) != "value2" {
		t.Errorf("Expected value2, got %v", val)
	}

	// Test integer value
	cache.Put("key3", int64(123))
	val, ok = cache.Get("key3")
	if !ok {
		t.Error("Expected to find key3")
	}
	if val.(int64) != 123 {
		t.Errorf("Expected 123, got %v", val)
	}
}

// TestGetNonExistent tests getting a non-existent key
func TestGetNonExistent(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	val, ok := cache.Get("nonexistent")
	if ok {
		t.Error("Expected not to find nonexistent key")
	}
	if val != nil {
		t.Errorf("Expected nil value, got %v", val)
	}
}

// TestPutWithExpires tests expiration
func TestPutWithExpires(t *testing.T) {
	cache, err := NewObjectCache(5*time.Minute, 100*time.Millisecond, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Put a value that expires quickly
	cache.PutWithExpires("key1", "value1", 200*time.Millisecond)

	// Should be present immediately
	val, ok := cache.Get("key1")
	if !ok || val != "value1" {
		t.Error("Expected to find key1 immediately")
	}

	// Wait for expiration
	time.Sleep(300 * time.Millisecond)

	// Should be gone
	_, ok = cache.Get("key1")
	if ok {
		t.Error("Expected key1 to be expired")
	}
}

// TestDelete tests deletion
func TestDelete(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	cache.Put("key1", "value1")

	// Verify it exists
	_, ok := cache.Get("key1")
	if !ok {
		t.Error("Expected to find key1")
	}

	// Delete it
	cache.Delete("key1")

	// Verify it's gone
	_, ok = cache.Get("key1")
	if ok {
		t.Error("Expected key1 to be deleted")
	}
}

// TestDeleteByPrefix tests prefix deletion
func TestDeleteByPrefix(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Add multiple keys with same prefix
	cache.Put("user:1:name", "Alice")
	cache.Put("user:1:email", "alice@example.com")
	cache.Put("user:2:name", "Bob")
	cache.Put("product:1", "Product1")

	// Delete all user:1 keys
	cache.DeleteByPrefix("user:1:")

	// Verify user:1 keys are gone
	if _, ok := cache.Get("user:1:name"); ok {
		t.Error("Expected user:1:name to be deleted")
	}
	if _, ok := cache.Get("user:1:email"); ok {
		t.Error("Expected user:1:email to be deleted")
	}

	// Verify user:2 and product keys still exist
	if _, ok := cache.Get("user:2:name"); !ok {
		t.Error("Expected user:2:name to still exist")
	}
	if _, ok := cache.Get("product:1"); !ok {
		t.Error("Expected product:1 to still exist")
	}
}

// TestGetKeys tests getting all keys
func TestGetKeys(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Empty cache
	keys := cache.GetKeys()
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}

	// Add some keys
	cache.Put("key1", "value1")
	cache.Put("key2", "value2")
	cache.Put("key3", "value3")

	keys = cache.GetKeys()
	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}

	// Verify all keys are present
	keyMap := make(map[string]bool)
	for _, key := range keys {
		keyMap[key] = true
	}
	if !keyMap["key1"] || !keyMap["key2"] || !keyMap["key3"] {
		t.Error("Not all keys were returned")
	}
}

// TestGetKeysByPrefix tests getting keys by prefix
func TestGetKeysByPrefix(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Add keys with different prefixes
	cache.Put("user:1:name", "Alice")
	cache.Put("user:1:email", "alice@example.com")
	cache.Put("user:2:name", "Bob")
	cache.Put("product:1", "Product1")
	cache.Put("product:2", "Product2")

	// Get user:1 keys
	keys := cache.GetKeysByPrefix("user:1:")
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys with prefix 'user:1:', got %d", len(keys))
	}

	// Get all user keys
	keys = cache.GetKeysByPrefix("user:")
	if len(keys) != 3 {
		t.Errorf("Expected 3 keys with prefix 'user:', got %d", len(keys))
	}

	// Get product keys
	keys = cache.GetKeysByPrefix("product:")
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys with prefix 'product:', got %d", len(keys))
	}

	// Get non-existent prefix
	keys = cache.GetKeysByPrefix("nonexistent:")
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys with prefix 'nonexistent:', got %d", len(keys))
	}
}

// TestLRUEviction tests LRU eviction by object count
func TestLRUEviction(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 3, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Add 3 items (at capacity)
	cache.Put("key1", "value1")
	cache.Put("key2", "value2")
	cache.Put("key3", "value3")

	// All should exist
	if _, ok := cache.Get("key1"); !ok {
		t.Error("Expected key1 to exist")
	}
	if _, ok := cache.Get("key2"); !ok {
		t.Error("Expected key2 to exist")
	}
	if _, ok := cache.Get("key3"); !ok {
		t.Error("Expected key3 to exist")
	}

	// Add 4th item, should evict least recently used (key1)
	cache.Put("key4", "value4")

	// key1 should be evicted
	if _, ok := cache.Get("key1"); ok {
		t.Error("Expected key1 to be evicted")
	}

	// Others should still exist
	if _, ok := cache.Get("key2"); !ok {
		t.Error("Expected key2 to exist")
	}
	if _, ok := cache.Get("key3"); !ok {
		t.Error("Expected key3 to exist")
	}
	if _, ok := cache.Get("key4"); !ok {
		t.Error("Expected key4 to exist")
	}
}

// TestLRUAccessPattern tests that accessing items updates LRU order
func TestLRUAccessPattern(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 2, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	// Access key1 to make it more recently used
	cache.Get("key1")

	// Add key3, should evict key2 (least recently used)
	cache.Put("key3", "value3")

	// key2 should be evicted
	if _, ok := cache.Get("key2"); ok {
		t.Error("Expected key2 to be evicted")
	}

	// key1 and key3 should exist
	if _, ok := cache.Get("key1"); !ok {
		t.Error("Expected key1 to exist")
	}
	if _, ok := cache.Get("key3"); !ok {
		t.Error("Expected key3 to exist")
	}
}

func TestLargeCacheAccessPromotesEventually(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 64, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	for i := 0; i < 64; i++ {
		cache.Put(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))
	}

	// Approximate LRU promotion on large caches is sampled. After enough hits,
	// key0 should be promoted and survive the next eviction.
	for i := 0; i < hitPromotionInterval; i++ {
		if _, ok := cache.Get("key0"); !ok {
			t.Fatal("expected key0 to exist")
		}
	}

	cache.Put("key64", "value64")

	if _, ok := cache.Get("key0"); !ok {
		t.Fatal("expected key0 to remain after sampled promotion")
	}
	if _, ok := cache.Get("key1"); ok {
		t.Fatal("expected key1 to be evicted after key0 promotion")
	}
}

// TestMemoryLimitEviction tests eviction based on memory limits
func TestMemoryLimitEviction(t *testing.T) {
	t.Parallel()
	// Set max memory to 150 bytes
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 150)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Add strings that total 150 bytes
	cache.Put("key1", strings.Repeat("a", 50)) // 50 bytes
	cache.Put("key2", strings.Repeat("b", 50)) // 50 bytes
	cache.Put("key3", strings.Repeat("c", 50)) // 50 bytes

	// Access key1 to make it most recently used
	// Order is now: key1 (front), key3, key2 (tail/LRU)
	if _, ok := cache.Get("key1"); !ok {
		t.Error("Expected key1 to exist")
	}

	// Add another 50 bytes, should trigger eviction of key2 (least recently used)
	cache.Put("key4", strings.Repeat("d", 50))

	// key2 should be evicted (it was the least recently used after we accessed key1)
	if _, ok := cache.Get("key2"); ok {
		t.Error("Expected key2 to be evicted due to memory limit")
	}

	// Others should exist
	if _, ok := cache.Get("key1"); !ok {
		t.Error("Expected key1 to exist")
	}
	if _, ok := cache.Get("key3"); !ok {
		t.Error("Expected key3 to exist")
	}
	if _, ok := cache.Get("key4"); !ok {
		t.Error("Expected key4 to exist")
	}
}

// TestConcurrency tests concurrent access
func TestConcurrency(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent puts and gets
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("key-%d-%d", id, j)
				value := fmt.Sprintf("value-%d-%d", id, j)
				cache.Put(key, value)

				if val, ok := cache.Get(key); ok {
					if val != value {
						t.Errorf("Expected %s, got %v", value, val)
					}
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestCleanup tests that expired entries are cleaned up
func TestCleanup(t *testing.T) {
	cache, err := NewObjectCache(5*time.Minute, 100*time.Millisecond, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Add entries with short expiration
	cache.PutWithExpires("key1", "value1", 150*time.Millisecond)
	cache.PutWithExpires("key2", "value2", 150*time.Millisecond)

	// Should exist initially
	if _, ok := cache.Get("key1"); !ok {
		t.Error("Expected key1 to exist initially")
	}

	// Wait for cleanup to run
	time.Sleep(300 * time.Millisecond)

	// Keys should be cleaned up
	if _, ok := cache.Get("key1"); ok {
		t.Error("Expected key1 to be cleaned up")
	}
	if _, ok := cache.Get("key2"); ok {
		t.Error("Expected key2 to be cleaned up")
	}
}

// TestCloseCloser tests that io.Closer values are closed
func TestCloseCloser(t *testing.T) {
	cache, err := NewObjectCache(5*time.Minute, 50*time.Millisecond, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	closer := &mockCloser{}
	cache.PutWithExpires("key1", closer, 100*time.Millisecond)

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	// Close cache
	cache.Close()

	// Verify closer was closed
	if !closer.IsClosed() {
		t.Error("Expected closer to be closed")
	}
}

// TestDoubleClose tests that closing twice doesn't panic
func TestDoubleClose(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	err1 := cache.Close()
	err2 := cache.Close()

	if err1 != nil {
		t.Errorf("First close returned error: %v", err1)
	}
	if err2 != nil {
		t.Errorf("Second close returned error: %v", err2)
	}
}

// TestCloseWithClosers tests that all io.Closer values are closed on cache Close
func TestCloseWithClosers(t *testing.T) {
	t.Parallel()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	closers := []*mockCloser{
		{},
		{},
		{},
	}

	for i, closer := range closers {
		cache.Put(fmt.Sprintf("key%d", i), closer)
	}

	cache.Close()

	// Verify all closers were closed
	for i, closer := range closers {
		if !closer.IsClosed() {
			t.Errorf("Expected closer %d to be closed", i)
		}
	}
}

// Benchmark tests

func BenchmarkPut(b *testing.B) {
	b.ReportAllocs()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i%1000)
		cache.Put(key, "value")
	}
}

func BenchmarkGet(b *testing.B) {
	b.ReportAllocs()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		cache.Put(fmt.Sprintf("key-%d", i), "value")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i%1000)
		cache.Get(key)
	}
}

func BenchmarkPutGet(b *testing.B) {
	b.ReportAllocs()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i%1000)
		cache.Put(key, "value")
		cache.Get(key)
	}
}

func BenchmarkConcurrentPutGet(b *testing.B) {
	b.ReportAllocs()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key-%d", i%1000)
			if i%2 == 0 {
				cache.Put(key, "value")
			} else {
				cache.Get(key)
			}
			i++
		}
	})
}

func BenchmarkLRUEviction(b *testing.B) {
	b.ReportAllocs()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 100, 0)
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i)
		cache.Put(key, "value")
	}
}

func BenchmarkDeleteByPrefix(b *testing.B) {
	b.ReportAllocs()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		cache.Put(fmt.Sprintf("prefix:%d", i), "value")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.DeleteByPrefix("prefix:")
		// Re-populate for next iteration
		if i < b.N-1 {
			for j := 0; j < 1000; j++ {
				cache.Put(fmt.Sprintf("prefix:%d", j), "value")
			}
		}
	}
}

func BenchmarkGetKeys(b *testing.B) {
	b.ReportAllocs()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		cache.Put(fmt.Sprintf("key-%d", i), "value")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.GetKeys()
	}
}

func BenchmarkGetKeysByPrefix(b *testing.B) {
	b.ReportAllocs()
	cache, err := NewObjectCache(5*time.Minute, 1*time.Minute, 0, 0)
	if err != nil {
		b.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Pre-populate cache with different prefixes
	for i := 0; i < 1000; i++ {
		cache.Put(fmt.Sprintf("prefix:%d", i), "value")
		cache.Put(fmt.Sprintf("other:%d", i), "value")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.GetKeysByPrefix("prefix:")
	}
}
