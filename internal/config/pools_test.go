package config

import (
	"bytes"
	"testing"
)

// TestBufferPoolReset ensures buffers are properly reset when returned to pool
func TestBufferPoolReset(t *testing.T) {
	// Get a buffer and write some data
	buf1 := getBuffer()
	*buf1 = append(*buf1, []byte("test data 1")...)
	
	if len(*buf1) == 0 {
		t.Error("buffer should contain data")
	}
	
	// Return it to pool
	putBuffer(buf1)
	
	// Get another buffer (should be the same one, now reset)
	buf2 := getBuffer()
	
	if len(*buf2) != 0 {
		t.Errorf("buffer should be reset to length 0, got length %d", len(*buf2))
	}
	
	if cap(*buf2) == 0 {
		t.Error("buffer capacity should be preserved")
	}
	
	putBuffer(buf2)
}

// TestSmallBufferPoolReset ensures small buffers are properly reset
func TestSmallBufferPoolReset(t *testing.T) {
	buf1 := getSmallBuffer()
	*buf1 = append(*buf1, []byte("small data")...)
	
	if len(*buf1) == 0 {
		t.Error("buffer should contain data")
	}
	
	putSmallBuffer(buf1)
	
	buf2 := getSmallBuffer()
	
	if len(*buf2) != 0 {
		t.Errorf("small buffer should be reset to length 0, got length %d", len(*buf2))
	}
	
	putSmallBuffer(buf2)
}

// TestBytesBufferPoolReset ensures bytes.Buffer is properly reset
func TestBytesBufferPoolReset(t *testing.T) {
	buf1 := getBytesBuffer()
	buf1.WriteString("test content")
	
	if buf1.Len() == 0 {
		t.Error("buffer should contain data")
	}
	
	putBytesBuffer(buf1)
	
	buf2 := getBytesBuffer()
	
	if buf2.Len() != 0 {
		t.Errorf("bytes.Buffer should be reset to length 0, got length %d", buf2.Len())
	}
	
	putBytesBuffer(buf2)
}

// TestStringSlicePoolReset ensures string slices are properly reset
func TestStringSlicePoolReset(t *testing.T) {
	slice1 := getStringSlice()
	*slice1 = append(*slice1, "key1", "key2", "key3")
	
	if len(*slice1) == 0 {
		t.Error("slice should contain data")
	}
	
	putStringSlice(slice1)
	
	slice2 := getStringSlice()
	
	if len(*slice2) != 0 {
		t.Errorf("string slice should be reset to length 0, got length %d", len(*slice2))
	}
	
	if cap(*slice2) == 0 {
		t.Error("string slice capacity should be preserved")
	}
	
	putStringSlice(slice2)
}

// TestMapPoolReset ensures maps are properly cleared
func TestMapPoolReset(t *testing.T) {
	map1 := getMap()
	map1["key1"] = "value1"
	map1["key2"] = "value2"
	map1["key3"] = "value3"
	
	if len(map1) == 0 {
		t.Error("map should contain data")
	}
	
	putMap(map1)
	
	map2 := getMap()
	
	if len(map2) != 0 {
		t.Errorf("map should be cleared, got %d entries", len(map2))
	}
	
	// Verify all keys are removed
	for key := range map2 {
		t.Errorf("map should be empty but contains key: %s", key)
	}
	
	putMap(map2)
}

// TestMapPoolSizeLimit ensures large maps are not returned to pool
func TestMapPoolSizeLimit(t *testing.T) {
	// Create a map larger than the limit (100 entries)
	largeMap := getMap()
	for i := 0; i < 150; i++ {
		largeMap[string(rune(i))] = i
	}
	
	if len(largeMap) <= 100 {
		t.Error("map should have more than 100 entries for this test")
	}
	
	// This should NOT return the map to the pool due to size
	putMap(largeMap)
	
	// Get a new map - it should be fresh, not the large one
	newMap := getMap()
	
	// The new map should be empty or have default capacity
	if len(newMap) > 16 {
		t.Errorf("expected fresh map with reasonable size, got %d entries", len(newMap))
	}
	
	putMap(newMap)
}

// TestBufferPoolSizeLimit ensures large buffers are not returned to pool
func TestBufferPoolSizeLimit(t *testing.T) {
	buf := getBuffer()
	
	// Grow buffer beyond limit (1MB)
	largeData := make([]byte, 2*1024*1024) // 2MB
	*buf = append(*buf, largeData...)
	
	if cap(*buf) <= 1024*1024 {
		t.Error("buffer capacity should exceed 1MB for this test")
	}
	
	// This should NOT return the buffer to pool due to size
	putBuffer(buf)
	
	// Getting a new buffer should give us one with reasonable capacity
	newBuf := getBuffer()
	
	if cap(*newBuf) > 1024*1024 {
		t.Errorf("expected buffer with reasonable capacity, got %d bytes", cap(*newBuf))
	}
	
	putBuffer(newBuf)
}

// TestBufferPool_OversizedDiscarded verifies that buffers grown beyond MaxPoolBufferSize
// are not returned to the pool, preventing unbounded memory growth.
func TestBufferPool_OversizedDiscarded(t *testing.T) {
	InitBufferPools()
	defer ShutdownBufferPools()

	// Get a buffer and grow it to 2MB (beyond the 1MB MaxPoolBufferSize)
	buf := getBuffer()
	oversized := make([]byte, 2*1024*1024)
	*buf = append(*buf, oversized...)

	if cap(*buf) <= MaxPoolBufferSize {
		t.Fatalf("buffer should exceed MaxPoolBufferSize for this test, got cap=%d", cap(*buf))
	}

	// Return it to pool (should be discarded, not pooled)
	putBuffer(buf)

	// Get a fresh buffer; it should NOT be the oversized one
	fresh := getBuffer()
	if cap(*fresh) > MaxPoolBufferSize {
		t.Errorf("expected fresh buffer with cap <= %d, got cap=%d", MaxPoolBufferSize, cap(*fresh))
	}

	putBuffer(fresh)
}

// TestRegexCacheHit ensures regex patterns are cached correctly
func TestRegexCacheHit(t *testing.T) {
	pattern := `\d+`
	
	// First call should compile and cache
	re1, err := getCompiledRegex(pattern)
	if err != nil {
		t.Fatalf("failed to compile regex: %v", err)
	}
	
	// Second call should return cached version
	re2, err := getCompiledRegex(pattern)
	if err != nil {
		t.Fatalf("failed to get cached regex: %v", err)
	}
	
	// Should be the exact same pointer (cached)
	if re1 != re2 {
		t.Error("regex should be cached and return same instance")
	}
	
	// Test that it works
	if !re1.MatchString("123") {
		t.Error("regex should match digits")
	}
}

// TestRegexCacheDifferentPatterns ensures different patterns are cached separately
func TestRegexCacheDifferentPatterns(t *testing.T) {
	pattern1 := `\d+`
	pattern2 := `[a-z]+`
	
	re1, err := getCompiledRegex(pattern1)
	if err != nil {
		t.Fatalf("failed to compile regex 1: %v", err)
	}
	
	re2, err := getCompiledRegex(pattern2)
	if err != nil {
		t.Fatalf("failed to compile regex 2: %v", err)
	}
	
	// Should be different patterns
	if re1 == re2 {
		t.Error("different patterns should have different regex instances")
	}
	
	// Both should work correctly
	if !re1.MatchString("123") {
		t.Error("pattern1 should match digits")
	}
	
	if !re2.MatchString("abc") {
		t.Error("pattern2 should match lowercase letters")
	}
}

// TestRegexCacheClear tests that cache can be cleared
func TestRegexCacheClear(t *testing.T) {
	pattern := `test_pattern_\d+`
	
	// Compile and cache a pattern
	_, err := getCompiledRegex(pattern)
	if err != nil {
		t.Fatalf("failed to compile regex: %v", err)
	}
	
	// Check cache has entries
	sizeBefore := getRegexCacheSize()
	if sizeBefore == 0 {
		t.Error("cache should have at least one entry")
	}
	
	// Clear cache
	clearRegexCache()
	
	// Check cache is empty
	sizeAfter := getRegexCacheSize()
	if sizeAfter != 0 {
		t.Errorf("cache should be empty after clear, got %d entries", sizeAfter)
	}
}

// TestConcurrentPoolAccess tests that pools are safe for concurrent use
func TestConcurrentPoolAccess(t *testing.T) {
	const goroutines = 100
	done := make(chan bool, goroutines)
	
	for i := 0; i < goroutines; i++ {
		go func() {
			// Test buffer pool
			buf := getBuffer()
			*buf = append(*buf, []byte("concurrent test")...)
			putBuffer(buf)
			
			// Test map pool
			m := getMap()
			m["test"] = "value"
			putMap(m)
			
			// Test bytes buffer pool
			bb := getBytesBuffer()
			bb.WriteString("concurrent")
			putBytesBuffer(bb)
			
			done <- true
		}()
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestPoolsReturnDifferentObjects verifies pools return different objects for concurrent use
func TestPoolsReturnDifferentObjects(t *testing.T) {
	// Get two buffers without returning first one
	buf1 := getBuffer()
	buf2 := getBuffer()
	
	// They should be different objects (different pointers)
	if buf1 == buf2 {
		t.Error("pools should return different objects when not returned yet")
	}
	
	// Modify both to ensure they're independent
	*buf1 = append(*buf1, []byte("buffer1")...)
	*buf2 = append(*buf2, []byte("buffer2")...)
	
	if bytes.Equal(*buf1, *buf2) {
		t.Error("buffers should be independent")
	}
	
	putBuffer(buf1)
	putBuffer(buf2)
}

