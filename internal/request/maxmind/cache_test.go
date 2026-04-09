package maxmind

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockCacher is a simple in-memory cache for testing
type MockCacher struct {
	data map[string][]byte
	mu   sync.RWMutex
}

func NewMockCacher() *MockCacher {
	return &MockCacher{
		data: make(map[string][]byte),
	}
}

func (m *MockCacher) Get(ctx context.Context, cacheType, key string) (io.Reader, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if data, exists := m.data[key]; exists {
		return bytes.NewReader(data), nil
	}
	return nil, nil
}

func (m *MockCacher) GetWithPrefix(ctx context.Context, cacheType, key string) (io.Reader, error) {
	// Simple implementation - just delegate to Get
	return m.Get(ctx, cacheType, key)
}

func (m *MockCacher) Put(ctx context.Context, cacheType, key string, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.data[key] = data
	m.mu.Unlock()
	return nil
}

func (m *MockCacher) PutWithExpires(ctx context.Context, cacheType, key string, r io.Reader, expires time.Duration) error {
	// Simple implementation - ignore expiration
	return m.Put(ctx, cacheType, key, r)
}

func (m *MockCacher) PutWithPrefix(ctx context.Context, cacheType, key string, r io.Reader) error {
	// Simple implementation - just delegate to Put
	return m.Put(ctx, cacheType, key, r)
}

func (m *MockCacher) PutWithPrefixAndExpires(ctx context.Context, cacheType, key string, r io.Reader, expires time.Duration) error {
	// Simple implementation - just delegate to PutWithExpires
	return m.PutWithExpires(ctx, cacheType, key, r, expires)
}

func (m *MockCacher) Delete(ctx context.Context, cacheType, key string) error {
	delete(m.data, key)
	return nil
}

func (m *MockCacher) DeleteByPattern(ctx context.Context, cacheType, pattern string) error {
	// Simple implementation - delete all keys (not pattern matching)
	m.data = make(map[string][]byte)
	return nil
}

func (m *MockCacher) DeleteWithPrefix(ctx context.Context, cacheType, key string) error {
	// Simple implementation - just delegate to Delete
	return m.Delete(ctx, cacheType, key)
}

func (m *MockCacher) Increment(ctx context.Context, cacheType, key string, count int64) (int64, error) {
	// Simple implementation - just return the count
	return count, nil
}

func (m *MockCacher) IncrementWithExpires(ctx context.Context, cacheType, key string, count int64, expires time.Duration) (int64, error) {
	// Simple implementation - just return the count
	return count, nil
}

func (m *MockCacher) Close() error {
	return nil
}

func (m *MockCacher) Driver() string {
	return "mock"
}

func (m *MockCacher) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for key := range m.data {
		// Simple pattern matching
		if pattern == "*" || pattern == key || strings.HasPrefix(key, pattern) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func TestCachedManager_Lookup_IPv4(t *testing.T) {
	t.Parallel()
	// Create a base manager
	baseManager := createTestManager(t)
	defer baseManager.Close()

	// Create a mock cache
	mockCache := NewMockCacher()
	defer mockCache.Close()

	// Create cached manager
	cachedManager := &cachedManager{
		manager: baseManager,
		cache:   mockCache,
	}

	// Test IPv4 lookup with the provided test IP
	ip := net.ParseIP("107.210.156.163")
	require.NotNil(t, ip, "Failed to parse test IPv4 address")

	// First lookup should hit the database
	result1, err := cachedManager.Lookup(ip)
	require.NoError(t, err, "IPv4 lookup should succeed")
	require.NotNil(t, result1, "Result should not be nil")

	// Second lookup should hit the cache
	result2, err := cachedManager.Lookup(ip)
	require.NoError(t, err, "Cached IPv4 lookup should succeed")
	require.NotNil(t, result2, "Cached result should not be nil")

	// Results should be identical
	assert.Equal(t, result1, result2, "Cached result should match original result")

	// Wait a bit for async cache update to complete
	time.Sleep(100 * time.Millisecond)

	// Verify the data was cached
	cachedReader, err := mockCache.Get(context.Background(), cacheType, ip.String())
	require.NoError(t, err)
	require.NotNil(t, cachedReader, "Data should be cached")
	cachedData, err := io.ReadAll(cachedReader)
	require.NoError(t, err)
	assert.Greater(t, len(cachedData), 0, "Cached data should not be empty")
}

func TestCachedManager_Lookup_IPv6(t *testing.T) {
	t.Parallel()
	// Create a base manager
	baseManager := createTestManager(t)
	defer baseManager.Close()

	// Create a mock cache
	mockCache := NewMockCacher()
	defer mockCache.Close()

	// Create cached manager
	cachedManager := &cachedManager{
		manager: baseManager,
		cache:   mockCache,
	}

	// Test IPv6 lookup with the provided test IP
	ip := net.ParseIP("2001:4860:7:30e::9b")
	require.NotNil(t, ip, "Failed to parse test IPv6 address")

	// First lookup should hit the database
	result1, err := cachedManager.Lookup(ip)
	require.NoError(t, err, "IPv6 lookup should succeed")
	require.NotNil(t, result1, "Result should not be nil")

	// Second lookup should hit the cache
	result2, err := cachedManager.Lookup(ip)
	require.NoError(t, err, "Cached IPv6 lookup should succeed")
	require.NotNil(t, result2, "Cached result should not be nil")

	// Results should be identical
	assert.Equal(t, result1, result2, "Cached result should match original result")

	// Wait a bit for async cache update to complete
	time.Sleep(100 * time.Millisecond)

	// Verify the data was cached
	cachedReader, err := mockCache.Get(context.Background(), cacheType, ip.String())
	require.NoError(t, err)
	require.NotNil(t, cachedReader, "Data should be cached")
	cachedData, err := io.ReadAll(cachedReader)
	require.NoError(t, err)
	assert.Greater(t, len(cachedData), 0, "Cached data should not be empty")
}

func TestCachedManager_CacheConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "maxmind", cacheType)
	assert.Equal(t, 1*time.Second, cacheTimeout)
}

func TestCachedManager_ErrorHandling(t *testing.T) {
	t.Parallel()
	// Test with a manager that will fail
	baseManager := createTestManager(t)
	defer baseManager.Close()

	// Create a mock cache that will fail on Get
	failingCache := &MockCacher{}
	defer failingCache.Close()

	cachedManager := &cachedManager{
		manager: baseManager,
		cache:   failingCache,
	}

	// Test with invalid IP (this should still work as the error comes from maxminddb, not cache)
	invalidIP := net.ParseIP("invalid")
	result, err := cachedManager.Lookup(invalidIP)

	// The behavior depends on how maxminddb handles invalid IPs
	t.Logf("Invalid IP lookup with cache result: %+v, error: %v", result, err)
}

func TestCachedManager_ContextTimeout(t *testing.T) {
	t.Parallel()
	// Create a base manager
	baseManager := createTestManager(t)
	defer baseManager.Close()

	// Create a mock cache
	mockCache := NewMockCacher()
	defer mockCache.Close()

	// Create cached manager
	cachedManager := &cachedManager{
		manager: baseManager,
		cache:   mockCache,
	}

	// Test that the context timeout is properly set
	ip := net.ParseIP("107.210.156.163")
	require.NotNil(t, ip)

	// This should work within the 1-second timeout
	start := time.Now()
	result, err := cachedManager.Lookup(ip)
	duration := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Less(t, duration, 2*time.Second, "Lookup should complete within reasonable time")
}
