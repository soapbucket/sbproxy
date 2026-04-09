package responsecache

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/request/geoip"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
	"github.com/soapbucket/sbproxy/internal/request/uaparser"
)

// TestResponseCacheExpiration_EndToEnd tests the complete flow of response cache expiration via message bus
func TestResponseCacheExpiration_EndToEnd(t *testing.T) {
	// Create test messenger
	testMessenger := NewTestMessengerForCacheExpiration()
	defer testMessenger.Close()

	// Create mock cache
	mockCache := NewMockKVStore()

	// Create mock manager with test messenger
	mgr := &mockManagerWithMessenger{
		mockManager: &mockManager{
			settings: manager.GlobalSettings{},
		},
		messenger: testMessenger,
	}

	// Add ListKeys method to mock cache for this test
	mockCacheWithListKeys := &mockCacheWithListKeys{
		MockKVStore: mockCache,
	}

	// Override GetCache to return mock cache
	mgrWithCache := &mockManagerWithCache{
		mockManagerWithMessenger: mgr,
		cache:                     mockCacheWithListKeys,
	}

	// Step 1: Cache multiple responses with different vary combinations
	t.Run("Step 1: Cache responses with different vary combinations", func(t *testing.T) {
		// Create responses with different Accept-Encoding values
		varyHeaders := []string{"Accept-Encoding"}

		// Response 1: gzip encoding
		req1 := httptest.NewRequest("GET", "http://example.com/api/users", nil)
		req1.Header.Set("Accept-Encoding", "gzip")
		cacheKey1 := generateResponseCacheKey(req1, varyHeaders)

		cached1 := &CachedResponse{
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"application/json"}},
			Body:    []byte(`{"users": [{"id": 1}]}`),
			Size:    25,
		}
		data1, _ := json.Marshal(cached1)
		mockCache.Put(context.Background(), ResponseCacheType, cacheKey1, bytes.NewReader(data1))

		// Response 2: br encoding
		req2 := httptest.NewRequest("GET", "http://example.com/api/users", nil)
		req2.Header.Set("Accept-Encoding", "br")
		cacheKey2 := generateResponseCacheKey(req2, varyHeaders)

		cached2 := &CachedResponse{
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"application/json"}},
			Body:    []byte(`{"users": [{"id": 1}]}`),
			Size:    25,
		}
		data2, _ := json.Marshal(cached2)
		mockCache.Put(context.Background(), ResponseCacheType, cacheKey2, bytes.NewReader(data2))

		// Response 3: Different URL (should not be expired)
		req3 := httptest.NewRequest("GET", "http://example.com/api/products", nil)
		req3.Header.Set("Accept-Encoding", "gzip")
		cacheKey3 := generateResponseCacheKey(req3, varyHeaders)

		cached3 := &CachedResponse{
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"application/json"}},
			Body:    []byte(`{"products": []}`),
			Size:    18,
		}
		data3, _ := json.Marshal(cached3)
		mockCache.Put(context.Background(), ResponseCacheType, cacheKey3, bytes.NewReader(data3))

		// Verify all are cached
		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey1); err != nil {
			t.Fatal("cacheKey1 should be in cache")
		}
		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey2); err != nil {
			t.Fatal("cacheKey2 should be in cache")
		}
		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey3); err != nil {
			t.Fatal("cacheKey3 should be in cache")
		}

		t.Logf("✓ Cached 3 responses")
		t.Logf("  cacheKey1: %s", cacheKey1)
		t.Logf("  cacheKey2: %s", cacheKey2)
		t.Logf("  cacheKey3: %s", cacheKey3)
	})

	// Step 2: Start the cache expiration subscriber
	t.Run("Step 2: Start cache expiration subscriber", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		topic := "response_cache_expiration"
		config := ResponseCacheExpirationConfig{
			Enabled:       true,
			NormalizeURL:  true,
			NormalizePath: true,
			DefaultMethod: "GET",
		}

		err := StartResponseCacheExpirationSubscriber(ctx, mgrWithCache, topic, config)
		if err != nil {
			t.Fatalf("Failed to start cache expiration subscriber: %v", err)
		}

		// Give subscriber time to initialize
		time.Sleep(50 * time.Millisecond)

		t.Logf("✓ Cache expiration subscriber started on topic: %s", topic)
	})

	// Step 3: Send expiration message for URL (pattern-based)
	t.Run("Step 3: Expire cache by URL pattern", func(t *testing.T) {
		ctx := context.Background()
		topic := "response_cache_expiration"

		// Send expiration message for /api/users
		err := testMessenger.SendCacheExpirationMessage(ctx, topic, "origin-123", "http://example.com/api/users", "GET", "")
		if err != nil {
			t.Fatalf("Failed to send expiration message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		t.Logf("✓ Sent expiration message for /api/users")
	})

	// Step 4: Verify all vary combinations for /api/users are expired
	t.Run("Step 4: Verify pattern-based expiration", func(t *testing.T) {
		// Give cache expiration time to complete
		time.Sleep(50 * time.Millisecond)

		varyHeaders := []string{"Accept-Encoding"}

		// Check cacheKey1 (gzip) - should be expired
		req1 := httptest.NewRequest("GET", "http://example.com/api/users", nil)
		req1.Header.Set("Accept-Encoding", "gzip")
		cacheKey1 := generateResponseCacheKey(req1, varyHeaders)

		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey1); err == nil {
			t.Error("cacheKey1 (gzip) should be expired")
		} else {
			t.Logf("✓ cacheKey1 (gzip) expired")
		}

		// Check cacheKey2 (br) - should be expired
		req2 := httptest.NewRequest("GET", "http://example.com/api/users", nil)
		req2.Header.Set("Accept-Encoding", "br")
		cacheKey2 := generateResponseCacheKey(req2, varyHeaders)

		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey2); err == nil {
			t.Error("cacheKey2 (br) should be expired")
		} else {
			t.Logf("✓ cacheKey2 (br) expired")
		}

		// Check cacheKey3 (products) - should NOT be expired
		req3 := httptest.NewRequest("GET", "http://example.com/api/products", nil)
		req3.Header.Set("Accept-Encoding", "gzip")
		cacheKey3 := generateResponseCacheKey(req3, varyHeaders)

		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey3); err != nil {
			t.Error("cacheKey3 (products) should NOT be expired")
		} else {
			t.Logf("✓ cacheKey3 (products) still in cache")
		}
	})

	// Step 5: Test exact cache key expiration
	t.Run("Step 5: Test exact cache key expiration", func(t *testing.T) {
		// Cache a new response
		varyHeaders := []string{"Accept-Encoding"}
		req := httptest.NewRequest("GET", "http://example.com/api/exact", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		cacheKey := generateResponseCacheKey(req, varyHeaders)

		cached := &CachedResponse{
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"application/json"}},
			Body:    []byte(`{"exact": true}`),
			Size:    15,
		}
		data, _ := json.Marshal(cached)
		mockCache.Put(context.Background(), ResponseCacheType, cacheKey, bytes.NewReader(data))

		// Verify it's cached
		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey); err != nil {
			t.Fatal("Response should be in cache")
		}

		// Send expiration message with exact cache key
		ctx := context.Background()
		topic := "response_cache_expiration"

		err := testMessenger.SendCacheExpirationMessage(ctx, topic, "origin-123", "", "", cacheKey)
		if err != nil {
			t.Fatalf("Failed to send expiration message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		// Verify exact cache key is expired
		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey); err == nil {
			t.Error("Exact cache key should be expired")
		} else {
			t.Logf("✓ Exact cache key expired: %s", cacheKey)
		}
	})

	// Step 6: Test URL normalization
	t.Run("Step 6: Test URL normalization", func(t *testing.T) {
		// Cache response without query params (to test normalization)
		varyHeaders := []string{"Accept-Encoding"}
		req := httptest.NewRequest("GET", "http://example.com/api/normalize", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		cacheKey := generateResponseCacheKey(req, varyHeaders)

		cached := &CachedResponse{
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"application/json"}},
			Body:    []byte(`{"normalized": true}`),
			Size:    20,
		}
		data, _ := json.Marshal(cached)
		mockCache.Put(context.Background(), ResponseCacheType, cacheKey, bytes.NewReader(data))

		// Verify it's cached
		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey); err != nil {
			t.Fatal("Response should be in cache")
		}

		// Send expiration message with normalized URL (trailing slash removed)
		ctx := context.Background()
		topic := "response_cache_expiration"

		// URL with trailing slash should expire the cached entry without trailing slash (normalization)
		err := testMessenger.SendCacheExpirationMessage(ctx, topic, "origin-123", "http://example.com/api/normalize/", "GET", "")
		if err != nil {
			t.Fatalf("Failed to send expiration message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		// Verify cache is expired (normalization should match)
		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey); err == nil {
			t.Error("Cache should be expired after normalization")
		} else {
			t.Logf("✓ Cache expired via URL normalization (trailing slash)")
		}
	})

	// Step 7: Test message with params only
	t.Run("Step 7: Test message with params only", func(t *testing.T) {
		// Cache a new response
		varyHeaders := []string{"Accept-Encoding"}
		req := httptest.NewRequest("GET", "http://example.com/api/params", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		cacheKey := generateResponseCacheKey(req, varyHeaders)

		cached := &CachedResponse{
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": []string{"application/json"}},
			Body:    []byte(`{"params": true}`),
			Size:    16,
		}
		data, _ := json.Marshal(cached)
		mockCache.Put(context.Background(), ResponseCacheType, cacheKey, bytes.NewReader(data))

		// Send expiration message with array format
		ctx := context.Background()
		topic := "response_cache_expiration"

		err := testMessenger.SendCacheExpirationMessage(ctx, topic, "origin-123", "http://example.com/api/params", "GET", "")
		if err != nil {
			t.Fatalf("Failed to send expiration message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		// Verify cache is expired
		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey); err == nil {
			t.Error("Cache should be expired")
		} else {
			t.Logf("✓ Cache expired via params-only message")
		}
	})
}

// mockManagerWithMessenger extends mockManager to return a messenger
type mockManagerWithMessenger struct {
	*mockManager
	messenger messenger.Messenger
}

func (m *mockManagerWithMessenger) GetMessenger() messenger.Messenger {
	return m.messenger
}

// mockCacheWithListKeys extends MockKVStore to add ListKeys and improve DeleteByPattern
type mockCacheWithListKeys struct {
	*MockKVStore
}

func (m *mockCacheWithListKeys) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	m.MockKVStore.mu.RLock()
	defer m.MockKVStore.mu.RUnlock()

	var keys []string
	for key := range m.MockKVStore.data {
		// Simple prefix matching for pattern
		if pattern == "" || (len(key) >= len(pattern) && key[:len(pattern)] == pattern) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *mockCacheWithListKeys) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	// Delegate to MockKVStore's DeleteByPattern which now handles hashed keys
	return m.MockKVStore.DeleteByPattern(ctx, cType, pattern)
}

// mockManagerWithCache extends mockManagerWithMessenger to return a cache
type mockManagerWithCache struct {
	*mockManagerWithMessenger
	cache cacher.Cacher
}

func (m *mockManagerWithCache) GetCache(level manager.CacheLevel) cacher.Cacher {
	if level == manager.L3Cache {
		return m.cache
	}
	return nil
}

// mockManager is a minimal manager implementation for testing
type mockManager struct {
	settings manager.GlobalSettings
}

func (m *mockManager) GetGlobalSettings() manager.GlobalSettings {
	return m.settings
}

func (m *mockManager) GetStorage() storage.Storage {
	return nil
}

func (m *mockManager) GetLocation(*http.Request) (*geoip.Result, error) {
	return nil, nil
}

func (m *mockManager) GetUserAgent(*http.Request) (*uaparser.Result, error) {
	return nil, nil
}

func (m *mockManager) EncryptString(string) (string, error) {
	return "", nil
}

func (m *mockManager) DecryptString(string) (string, error) {
	return "", nil
}

func (m *mockManager) EncryptStringWithContext(data string, context string) (string, error) {
	return data, nil
}

func (m *mockManager) DecryptStringWithContext(data string, context string) (string, error) {
	return data, nil
}

func (m *mockManager) SignString(string) (string, error) {
	return "", nil
}

func (m *mockManager) VerifyString(string, string) (bool, error) {
	return true, nil
}

func (m *mockManager) GetSessionCache() manager.SessionCache {
	return nil
}

func (m *mockManager) GetCache(level manager.CacheLevel) cacher.Cacher {
	return nil
}

func (m *mockManager) GetMessenger() messenger.Messenger {
	return nil
}

func (m *mockManager) GetServerContext() context.Context {
	return context.Background()
}

func (m *mockManager) GetCallbackPool() manager.WorkerPool {
	return nil
}

func (m *mockManager) GetCachePool() manager.WorkerPool {
	return nil
}

func (m *mockManager) Close() error {
	return nil
}

