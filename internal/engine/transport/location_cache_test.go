package transport

import (
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/graymeta/stow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocationCache_Basic(t *testing.T) {
	config := LocationCacheConfig{
		TTL:              10 * time.Second,
		CleanupInterval:  1 * time.Second,
		MaxIdleLocations: 10,
	}

	cache := NewLocationCache(config)
	defer cache.Close()

	// Test by manually adding locations to cache
	id := "test-id-1"
	cache.mu.Lock()
	cache.locations[id] = &CachedLocation{
		location:  &mockLocation{},
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		useCount:  1,
		kind:      "s3",
		id:        id,
	}
	cache.mu.Unlock()

	// Check stats
	stats := cache.GetStats()
	assert.Equal(t, 1, stats.Size, "Cache should have one entry")
	assert.Equal(t, 10, stats.MaxSize, "Max size should be configured value")
}

func TestLocationCache_Expiration(t *testing.T) {
	config := LocationCacheConfig{
		TTL:              100 * time.Millisecond, // Very short TTL for testing
		CleanupInterval:  50 * time.Millisecond,
		MaxIdleLocations: 10,
	}

	cache := NewLocationCache(config)
	defer cache.Close()

	// Simulate cached location by directly adding to cache
	id := "test-id"
	cache.mu.Lock()
	cache.locations[id] = &CachedLocation{
		location:  nil,                                     // Mock location
		createdAt: time.Now().Add(-200 * time.Millisecond), // Already expired
		lastUsed:  time.Now().Add(-200 * time.Millisecond),
		useCount:  1,
		kind:      "s3",
		id:        id,
	}
	cache.mu.Unlock()

	// Wait for cleanup
	time.Sleep(150 * time.Millisecond)

	// Check that expired location was removed
	cache.mu.RLock()
	_, exists := cache.locations[id]
	cache.mu.RUnlock()

	assert.False(t, exists, "Expired location should be removed")
}

func TestLocationCache_Eviction(t *testing.T) {
	config := LocationCacheConfig{
		TTL:              1 * time.Minute,
		CleanupInterval:  50 * time.Millisecond, // Short interval for testing
		MaxIdleLocations: 2,                     // Very small cache for testing eviction
	}

	cache := NewLocationCache(config)
	defer cache.Close()

	// Add locations to cache
	for i := 0; i < 3; i++ {
		id := getID(Settings{"test": string(rune('a' + i))})

		cache.mu.Lock()
		cache.locations[id] = &CachedLocation{
			location:  &mockLocation{},
			createdAt: time.Now(),
			lastUsed:  time.Now().Add(-time.Duration(i) * time.Second), // Make them different ages
			useCount:  1,
			kind:      "s3",
			id:        id,
		}
		cache.mu.Unlock()
	}

	// Wait for cleanup loop to run and evict
	time.Sleep(200 * time.Millisecond)

	// Should have evicted oldest location
	stats := cache.GetStats()
	assert.LessOrEqual(t, stats.Size, 2, "Cache should not exceed max size")
}

func TestLocationCache_ConcurrentAccess(t *testing.T) {
	config := LocationCacheConfig{
		TTL:              1 * time.Minute,
		CleanupInterval:  10 * time.Second,
		MaxIdleLocations: 100,
	}

	cache := NewLocationCache(config)
	defer cache.Close()

	// Pre-populate cache with mock locations
	numLocations := 10
	for i := 0; i < numLocations; i++ {
		id := getID(Settings{"test": string(rune('a' + i))})

		cache.mu.Lock()
		cache.locations[id] = &CachedLocation{
			location:  &mockLocation{},
			createdAt: time.Now(),
			lastUsed:  time.Now(),
			useCount:  0,
			kind:      "s3",
			id:        id,
		}
		cache.mu.Unlock()
	}

	// Concurrent reads and writes limited to cache internals
	var wg sync.WaitGroup
	numGoroutines := 50
	numOperations := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				id := getID(Settings{"test": string(rune('a' + (j % numLocations)))})
				switch j % 3 {
				case 0:
					_ = cache.GetStats()
				case 1:
					cache.remove(id)
				case 2:
					cache.mu.Lock()
					cache.locations[id] = &CachedLocation{
						location:  &mockLocation{},
						createdAt: time.Now(),
						lastUsed:  time.Now(),
						useCount:  0,
						kind:      "s3",
						id:        id,
					}
					cache.mu.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()

	// Should not panic and cache should still be functional
	stats := cache.GetStats()
	assert.GreaterOrEqual(t, stats.MaxSize, stats.Size, "Size should not exceed max")
}

func TestLocationCache_Stats(t *testing.T) {
	config := DefaultLocationCacheConfig()
	cache := NewLocationCache(config)
	defer cache.Close()

	// Add some mock locations
	for i := 0; i < 5; i++ {
		id := getID(Settings{"test": string(rune('a' + i))})

		cache.mu.Lock()
		cache.locations[id] = &CachedLocation{
			location:  nil,
			createdAt: time.Now().Add(-time.Duration(i) * time.Minute),
			lastUsed:  time.Now().Add(-time.Duration(i) * time.Second),
			useCount:  int64(i + 1),
			kind:      "s3",
			id:        id,
		}
		cache.mu.Unlock()
	}

	stats := cache.GetStats()

	assert.Equal(t, 5, stats.Size, "Should have 5 cached locations")
	assert.Equal(t, config.MaxIdleLocations, stats.MaxSize)
	assert.Equal(t, config.TTL, stats.TTL)
	assert.Greater(t, stats.OldestAge, 0*time.Second)
	assert.Greater(t, stats.TotalUses, int64(0))
	assert.Len(t, stats.Locations, 5)

	// Test String representation
	str := stats.String()
	assert.Contains(t, str, "LocationCache")
	assert.Contains(t, str, "size=5")
}

func TestLocationCache_Clear(t *testing.T) {
	config := DefaultLocationCacheConfig()
	cache := NewLocationCache(config)
	defer cache.Close()

	// Add some mock locations
	for i := 0; i < 5; i++ {
		id := getID(Settings{"test": string(rune('a' + i))})

		cache.mu.Lock()
		cache.locations[id] = &CachedLocation{
			location:  nil,
			createdAt: time.Now(),
			lastUsed:  time.Now(),
			useCount:  1,
			kind:      "s3",
			id:        id,
		}
		cache.mu.Unlock()
	}

	// Verify locations exist
	stats := cache.GetStats()
	assert.Equal(t, 5, stats.Size)

	// Clear cache
	cache.Clear()

	// Verify cache is empty
	stats = cache.GetStats()
	assert.Equal(t, 0, stats.Size)
}

func TestLocationCache_Close(t *testing.T) {
	config := DefaultLocationCacheConfig()
	cache := NewLocationCache(config)

	// Add some locations
	for i := 0; i < 3; i++ {
		id := getID(Settings{"test": string(rune('a' + i))})

		cache.mu.Lock()
		cache.locations[id] = &CachedLocation{
			location:  nil,
			createdAt: time.Now(),
			lastUsed:  time.Now(),
			useCount:  1,
			kind:      "s3",
			id:        id,
		}
		cache.mu.Unlock()
	}

	// Close cache
	err := cache.Close()
	assert.NoError(t, err)

	// Verify cleanup goroutine stopped
	select {
	case <-cache.cleanupDone:
		// Good - cleanup finished
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Cleanup goroutine did not stop")
	}

	// Verify cache is empty
	stats := cache.GetStats()
	assert.Equal(t, 0, stats.Size)
}

func TestGlobalLocationCache(t *testing.T) {
	// Clean up any existing global cache
	CloseGlobalLocationCache()

	// Get global cache (should create new one)
	cache1 := GetGlobalLocationCache()
	require.NotNil(t, cache1)

	// Get again (should return same instance)
	cache2 := GetGlobalLocationCache()
	assert.Equal(t, cache1, cache2)

	// Set custom cache
	customConfig := LocationCacheConfig{
		TTL:              30 * time.Second,
		MaxIdleLocations: 50,
	}
	customCache := NewLocationCache(customConfig)
	SetGlobalLocationCache(customCache)

	// Get should return custom cache
	cache3 := GetGlobalLocationCache()
	assert.Equal(t, customCache, cache3)
	assert.NotEqual(t, cache1, cache3)

	// Clean up
	CloseGlobalLocationCache()
}

func TestCachedLocation_IsExpired(t *testing.T) {
	cached := &CachedLocation{
		createdAt: time.Now().Add(-5 * time.Minute),
	}

	// Test with shorter TTL (should be expired)
	assert.True(t, cached.IsExpired(1*time.Minute))

	// Test with longer TTL (should not be expired)
	assert.False(t, cached.IsExpired(10*time.Minute))
}

func TestCachedLocation_IsHealthy(t *testing.T) {
	// Healthy location (has non-nil location)
	cached := &CachedLocation{
		location: &mockLocation{},
	}
	assert.True(t, cached.IsHealthy())

	// Unhealthy location (nil location)
	cached = &CachedLocation{
		location: nil,
	}
	assert.False(t, cached.IsHealthy())
}

func TestDefaultLocationCacheConfig(t *testing.T) {
	config := DefaultLocationCacheConfig()

	assert.Equal(t, defaultLocationTTL, config.TTL)
	assert.Equal(t, defaultCleanupInterval, config.CleanupInterval)
	assert.Equal(t, defaultMaxIdleLocations, config.MaxIdleLocations)
	assert.False(t, config.EnableHealthCheck)
}

func TestNewLocationCache_ConfigDefaults(t *testing.T) {
	// Test with zero values - should use defaults
	config := LocationCacheConfig{}
	cache := NewLocationCache(config)
	defer cache.Close()

	assert.Equal(t, defaultLocationTTL, cache.ttl)
	assert.Equal(t, defaultCleanupInterval, cache.cleanupInterval)
	assert.Equal(t, defaultMaxIdleLocations, cache.maxIdleLocations)
}

// Benchmark tests
func BenchmarkLocationCache_Get_Hit(b *testing.B) {
	b.ReportAllocs()
	config := DefaultLocationCacheConfig()
	cache := NewLocationCache(config)
	defer cache.Close()

	// Pre-populate cache with mock location
	id := getID(Settings{"test": "benchmark"})
	cache.mu.Lock()
	cache.locations[id] = &CachedLocation{
		location:  &mockLocation{},
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		useCount:  0,
		kind:      "s3",
		id:        id,
	}
	cache.mu.Unlock()

	settings := Settings{"test": "benchmark"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cache.Get("s3", settings)
	}
}

func BenchmarkLocationCache_GetStats(b *testing.B) {
	b.ReportAllocs()
	config := DefaultLocationCacheConfig()
	cache := NewLocationCache(config)
	defer cache.Close()

	// Pre-populate with some locations
	for i := 0; i < 10; i++ {
		id := getID(Settings{"test": string(rune('a' + i))})
		cache.mu.Lock()
		cache.locations[id] = &CachedLocation{
			location:  &mockLocation{},
			createdAt: time.Now(),
			lastUsed:  time.Now(),
			useCount:  1,
			kind:      "s3",
			id:        id,
		}
		cache.mu.Unlock()
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = cache.GetStats()
	}
}

func BenchmarkLocationCache_Concurrent(b *testing.B) {
	b.ReportAllocs()
	config := DefaultLocationCacheConfig()
	cache := NewLocationCache(config)
	defer cache.Close()

	// Pre-populate with locations
	for i := 0; i < 10; i++ {
		id := getID(Settings{"test": string(rune('a' + i))})
		cache.mu.Lock()
		cache.locations[id] = &CachedLocation{
			location:  &mockLocation{},
			createdAt: time.Now(),
			lastUsed:  time.Now(),
			useCount:  0,
			kind:      "s3",
			id:        id,
		}
		cache.mu.Unlock()
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			settings := Settings{"test": string(rune('a' + (i % 10)))}
			cache.Get("s3", settings)
			i++
		}
	})
}

// Mock location for testing
// Note: Implements stow.Location interface for testing purposes
type mockLocation struct{}

func (m *mockLocation) CreateContainer(string) (stow.Container, error) { return nil, nil }
func (m *mockLocation) Containers(string, string, int) ([]stow.Container, string, error) {
	return nil, "", nil
}
func (m *mockLocation) Container(string) (stow.Container, error) { return nil, nil }
func (m *mockLocation) RemoveContainer(string) error             { return nil }
func (m *mockLocation) ItemByURL(*url.URL) (stow.Item, error)    { return nil, nil }
func (m *mockLocation) Close() error                             { return nil }
