package responsecache

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

// TestExpireResponseCache_PatternBased tests pattern-based cache expiration
func TestExpireResponseCache_PatternBased(t *testing.T) {
	mockCache := NewMockKVStore()
	mgr := &mockManagerWithCacheForTest{
		cache: &mockCacheWithListKeys{MockKVStore: mockCache},
	}

	// Cache multiple responses with different vary combinations
	varyHeaders := []string{"Accept-Encoding"}

	// Cache entry 1: gzip
	req1 := httptest.NewRequest("GET", "http://example.com/api/users", nil)
	req1.Header.Set("Accept-Encoding", "gzip")
	cacheKey1 := generateResponseCacheKey(req1, varyHeaders)
	cached1 := &CachedResponse{Status: 200, Body: []byte("gzip"), Size: 4}
	data1, _ := json.Marshal(cached1)
	mockCache.Put(context.Background(), ResponseCacheType, cacheKey1, bytes.NewReader(data1))

	// Cache entry 2: br
	req2 := httptest.NewRequest("GET", "http://example.com/api/users", nil)
	req2.Header.Set("Accept-Encoding", "br")
	cacheKey2 := generateResponseCacheKey(req2, varyHeaders)
	cached2 := &CachedResponse{Status: 200, Body: []byte("br"), Size: 2}
	data2, _ := json.Marshal(cached2)
	mockCache.Put(context.Background(), ResponseCacheType, cacheKey2, bytes.NewReader(data2))

	// Cache entry 3: different URL (should not be expired)
	req3 := httptest.NewRequest("GET", "http://example.com/api/products", nil)
	req3.Header.Set("Accept-Encoding", "gzip")
	cacheKey3 := generateResponseCacheKey(req3, varyHeaders)
	cached3 := &CachedResponse{Status: 200, Body: []byte("products"), Size: 8}
	data3, _ := json.Marshal(cached3)
	mockCache.Put(context.Background(), ResponseCacheType, cacheKey3, bytes.NewReader(data3))

	// Expire by URL pattern
	msg := ResponseCacheExpirationMessage{
		OriginID: "origin-123",
		URL:      "http://example.com/api/users",
		Method:   "GET",
	}
	config := ResponseCacheExpirationConfig{
		Enabled:       true,
		NormalizeURL:  true,
		NormalizePath: true,
		DefaultMethod: "GET",
	}

	err := ExpireResponseCache(context.Background(), mgr, msg, config)
	if err != nil {
		t.Fatalf("ExpireResponseCache failed: %v", err)
	}

	// Verify cacheKey1 is expired
	if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey1); err == nil {
		t.Error("cacheKey1 should be expired")
	}

	// Verify cacheKey2 is expired
	if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey2); err == nil {
		t.Error("cacheKey2 should be expired")
	}

	// Verify cacheKey3 is NOT expired
	if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey3); err != nil {
		t.Error("cacheKey3 should NOT be expired")
	}
}

// TestExpireResponseCache_ExactKey tests exact cache key expiration
func TestExpireResponseCache_ExactKey(t *testing.T) {
	mockCache := NewMockKVStore()
	mgr := &mockManagerWithCacheForTest{
		cache: &mockCacheWithListKeys{MockKVStore: mockCache},
	}

	// Cache a response
	varyHeaders := []string{"Accept-Encoding"}
	req := httptest.NewRequest("GET", "http://example.com/api/exact", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	cacheKey := generateResponseCacheKey(req, varyHeaders)

	cached := &CachedResponse{Status: 200, Body: []byte("exact"), Size: 5}
	data, _ := json.Marshal(cached)
	mockCache.Put(context.Background(), ResponseCacheType, cacheKey, bytes.NewReader(data))

	// Verify it's cached
	if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey); err != nil {
		t.Fatal("Response should be in cache")
	}

	// Expire by exact cache key
	msg := ResponseCacheExpirationMessage{
		OriginID: "origin-123",
		CacheKey: cacheKey,
	}
	config := ResponseCacheExpirationConfig{
		Enabled: true,
	}

	err := ExpireResponseCache(context.Background(), mgr, msg, config)
	if err != nil {
		t.Fatalf("ExpireResponseCache failed: %v", err)
	}

	// Verify cache is expired
	if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey); err == nil {
		t.Error("Cache should be expired")
	}
}

// TestNormalizeURLForCache tests URL normalization
func TestNormalizeURLForCache(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		config   ResponseCacheExpirationConfig
		expected string
	}{
		{
			name:   "normalize query params",
			rawURL: "http://example.com/api/users?page=1&limit=10",
			config: ResponseCacheExpirationConfig{
				NormalizeURL:  true,
				NormalizePath: false,
			},
			expected: "http://example.com/api/users",
		},
		{
			name:   "normalize trailing slash",
			rawURL: "http://example.com/api/users/",
			config: ResponseCacheExpirationConfig{
				NormalizeURL:  false,
				NormalizePath: true,
			},
			expected: "http://example.com/api/users",
		},
		{
			name:   "normalize both",
			rawURL: "http://example.com/api/users/?page=1",
			config: ResponseCacheExpirationConfig{
				NormalizeURL:  true,
				NormalizePath: true,
			},
			expected: "http://example.com/api/users",
		},
		{
			name:   "no normalization",
			rawURL: "http://example.com/api/users?page=1",
			config: ResponseCacheExpirationConfig{
				NormalizeURL:  false,
				NormalizePath: false,
			},
			expected: "http://example.com/api/users?page=1",
		},
		{
			name:   "path only",
			rawURL: "/api/users?page=1",
			config: ResponseCacheExpirationConfig{
				NormalizeURL:  true,
				NormalizePath: true,
			},
			expected: "/api/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeURLForCache(tt.rawURL, tt.config)
			if result != tt.expected {
				t.Errorf("normalizeURLForCache() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestHandleMessage_ResponseCacheExpiration tests message handling
func TestHandleMessage_ResponseCacheExpiration(t *testing.T) {
	mockCache := NewMockKVStore()
	testMessenger := NewTestMessengerForCacheExpiration()
	defer testMessenger.Close()

	mgr := &mockManagerWithCacheForTest{
		cache: &mockCacheWithListKeys{MockKVStore: mockCache},
	}

	mgrWithMessenger := &mockManagerWithMessengerForTest{
		mockManagerWithCacheForTest: mgr,
		messenger:                   testMessenger,
	}

	// Cache a response
	varyHeaders := []string{"Accept-Encoding"}
	req := httptest.NewRequest("GET", "http://example.com/api/test", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	cacheKey := generateResponseCacheKey(req, varyHeaders)

	cached := &CachedResponse{Status: 200, Body: []byte("test"), Size: 4}
	data, _ := json.Marshal(cached)
	mockCache.Put(context.Background(), ResponseCacheType, cacheKey, bytes.NewReader(data))

	// Start subscriber with unique topic per test to avoid sync.Once conflicts
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use unique topic to avoid sync.Once conflicts between tests
	topic := "test_topic_response_cache_" + t.Name()
	config := ResponseCacheExpirationConfig{
		Enabled:       true,
		NormalizeURL:  true,
		NormalizePath: true,
		DefaultMethod: "GET",
	}

	// Reset the sync.Once for testing
	ResetResponseCacheExpirationSubscriber()

	err := StartResponseCacheExpirationSubscriber(ctx, mgrWithMessenger, topic, config)
	if err != nil {
		t.Fatalf("Failed to start subscriber: %v", err)
	}

	// Wait for subscriber to be ready by checking if messenger has subscriber
	// The test messenger subscribes synchronously, so we just need a small delay
	time.Sleep(10 * time.Millisecond)

	// Send message (array format)
	batch := ResponseCacheExpirationBatch{
		Updates: []ResponseCacheExpirationMessage{{
			OriginID: "origin-123",
			URL:      "http://example.com/api/test",
			Method:   "GET",
		}},
	}
	body, _ := json.Marshal(batch)

	err = testMessenger.Send(ctx, topic, &messenger.Message{
		Body:    body,
		Channel: topic,
		Params:  make(map[string]string),
	})
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Wait for message processing with retries
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		time.Sleep(20 * time.Millisecond)
		if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey); err != nil {
			// Cache is expired, test passed
			return
		}
	}

	// Verify cache is expired
	if _, err := mockCache.Get(context.Background(), ResponseCacheType, cacheKey); err == nil {
		t.Error("Cache should be expired")
	}
}

// Helper types for testing
type mockManagerWithCacheForTest struct {
	cache cacher.Cacher
}

func (m *mockManagerWithCacheForTest) GetCache(level manager.CacheLevel) cacher.Cacher {
	if level == manager.L3Cache {
		return m.cache
	}
	return nil
}

func (m *mockManagerWithCacheForTest) GetGlobalSettings() manager.GlobalSettings {
	return manager.GlobalSettings{}
}

func (m *mockManagerWithCacheForTest) GetStorage() storage.Storage {
	return nil
}

func (m *mockManagerWithCacheForTest) EncryptString(string) (string, error) {
	return "", nil
}

func (m *mockManagerWithCacheForTest) DecryptString(string) (string, error) {
	return "", nil
}

func (m *mockManagerWithCacheForTest) EncryptStringWithContext(data string, context string) (string, error) {
	return data, nil
}

func (m *mockManagerWithCacheForTest) DecryptStringWithContext(data string, context string) (string, error) {
	return data, nil
}

func (m *mockManagerWithCacheForTest) SignString(string) (string, error) {
	return "", nil
}

func (m *mockManagerWithCacheForTest) VerifyString(string, string) (bool, error) {
	return true, nil
}

func (m *mockManagerWithCacheForTest) GetSessionCache() manager.SessionCache {
	return nil
}

func (m *mockManagerWithCacheForTest) GetMessenger() messenger.Messenger {
	return nil
}

func (m *mockManagerWithCacheForTest) GetServerContext() context.Context {
	return context.Background()
}

func (m *mockManagerWithCacheForTest) GetCallbackPool() manager.WorkerPool {
	return nil
}

func (m *mockManagerWithCacheForTest) GetCachePool() manager.WorkerPool {
	return nil
}

func (m *mockManagerWithCacheForTest) Close() error {
	return nil
}

type mockManagerWithMessengerForTest struct {
	*mockManagerWithCacheForTest
	messenger messenger.Messenger
}

func (m *mockManagerWithMessengerForTest) GetMessenger() messenger.Messenger {
	return m.messenger
}
