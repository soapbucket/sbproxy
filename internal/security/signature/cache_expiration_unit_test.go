package signature

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

// mockCacheWithListKeysForSignature extends MockKVStore to add ListKeys for signature cache tests
type mockCacheWithListKeysForSignature struct {
	*MockKVStore
}

func (m *mockCacheWithListKeysForSignature) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	m.MockKVStore.mu.RLock()
	defer m.MockKVStore.mu.RUnlock()

	prefix := cType + ":"
	var keys []string
	for fullKey := range m.MockKVStore.data {
		// Extract key part (after cType + ":")
		if len(fullKey) > len(prefix) && fullKey[:len(prefix)] == prefix {
			key := fullKey[len(prefix):]
			// Simple prefix matching for pattern
			if pattern == "" || (len(key) >= len(pattern) && key[:len(pattern)] == pattern) {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
}

// MockKVStore is a simple in-memory cache for testing (reusing from handler package pattern)
type MockKVStore struct {
	data map[string][]byte
	mu   sync.RWMutex
}

func NewMockKVStore() *MockKVStore {
	return &MockKVStore{
		data: make(map[string][]byte),
	}
}

func (m *MockKVStore) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	fullKey := cType + ":" + key
	if data, exists := m.data[fullKey]; exists {
		return bytes.NewReader(data), nil
	}
	return nil, cacher.ErrNotFound
}

func (m *MockKVStore) Put(ctx context.Context, cType string, key string, value io.Reader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := io.ReadAll(value)
	if err != nil {
		return err
	}
	fullKey := cType + ":" + key
	m.data[fullKey] = data
	return nil
}

func (m *MockKVStore) PutWithExpires(ctx context.Context, cType string, key string, value io.Reader, duration time.Duration) error {
	return m.Put(ctx, cType, key, value)
}

func (m *MockKVStore) Delete(ctx context.Context, cType string, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fullKey := cType + ":" + key
	delete(m.data, fullKey)
	return nil
}

func (m *MockKVStore) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Remove wildcard suffix for pattern matching
	patternPrefix := pattern
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		patternPrefix = pattern[:len(pattern)-1]
	}
	for key := range m.data {
		if patternPrefix == "" || (len(key) >= len(patternPrefix) && key[:len(patternPrefix)] == patternPrefix) {
			delete(m.data, key)
		}
	}
	return nil
}

func (m *MockKVStore) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	return count, nil
}

func (m *MockKVStore) IncrementWithExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	return m.Increment(ctx, cType, key, count)
}

func (m *MockKVStore) Close() error {
	return nil
}

func (m *MockKVStore) Driver() string {
	return "mock"
}

// WithPrefix methods
func (m *MockKVStore) GetWithPrefix(ctx context.Context, cType string, key string) (io.Reader, error) {
	return m.Get(ctx, cType, key)
}

func (m *MockKVStore) PutWithPrefix(ctx context.Context, cType string, key string, value io.Reader) error {
	return m.Put(ctx, cType, key, value)
}

func (m *MockKVStore) PutWithPrefixAndExpires(ctx context.Context, cType string, key string, value io.Reader, expires time.Duration) error {
	return m.PutWithExpires(ctx, cType, key, value, expires)
}

func (m *MockKVStore) DeleteWithPrefix(ctx context.Context, cType string, key string) error {
	return m.Delete(ctx, cType, key)
}

func (m *MockKVStore) DeleteWithPrefixByPattern(ctx context.Context, cType string, pattern string) error {
	return m.DeleteByPattern(ctx, cType, pattern)
}

func (m *MockKVStore) IncrementWithPrefix(ctx context.Context, cType string, key string, count int64) (int64, error) {
	return m.Increment(ctx, cType, key, count)
}

func (m *MockKVStore) IncrementWithPrefixAndExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	return m.IncrementWithExpires(ctx, cType, key, count, expires)
}

// TestExpireSignatureCache_ExactKey tests exact cache key expiration
func TestExpireSignatureCache_ExactKey(t *testing.T) {
	mockCache := NewMockKVStore()
	mgr := &mockManagerWithCacheForTest{
		cache: &mockCacheWithListKeysForSignature{MockKVStore: mockCache},
	}

	// Cache a signature-verified response
	cacheKey := "test-cache-key-123"
	cachedData := []byte(`{"status_code":200,"body":"test"}`)
	mockCache.Put(context.Background(), signatureCachePrefix, cacheKey, bytes.NewReader(cachedData))

	// Verify it's cached
	if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey); err != nil {
		t.Fatal("Signature cache entry should be in cache")
	}

	// Expire by exact cache key
	msg := SignatureCacheExpirationMessage{
		OriginID: "origin-123",
		CacheKey: cacheKey,
	}
	config := SignatureCacheExpirationConfig{
		Enabled: true,
	}

	err := ExpireSignatureCache(context.Background(), mgr, msg, config)
	if err != nil {
		t.Fatalf("ExpireSignatureCache failed: %v", err)
	}

	// Verify cache is expired
	if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey); err == nil {
		t.Error("Signature cache should be expired")
	}
}

// TestExpireSignatureCache_URLBased tests URL-based expiration (deletes all keys)
func TestExpireSignatureCache_URLBased(t *testing.T) {
	mockCache := NewMockKVStore()
	mgr := &mockManagerWithCacheForTest{
		cache: &mockCacheWithListKeysForSignature{MockKVStore: mockCache},
	}

	// Cache multiple signature-verified responses
	cacheKey1 := "test-cache-key-1"
	cacheKey2 := "test-cache-key-2"
	cacheKey3 := "test-cache-key-3"

	cachedData1 := []byte(`{"status_code":200,"body":"test1"}`)
	cachedData2 := []byte(`{"status_code":200,"body":"test2"}`)
	cachedData3 := []byte(`{"status_code":200,"body":"test3"}`)

	mockCache.Put(context.Background(), signatureCachePrefix, cacheKey1, bytes.NewReader(cachedData1))
	mockCache.Put(context.Background(), signatureCachePrefix, cacheKey2, bytes.NewReader(cachedData2))
	mockCache.Put(context.Background(), signatureCachePrefix, cacheKey3, bytes.NewReader(cachedData3))

	// Verify all are cached
	if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey1); err != nil {
		t.Fatal("cacheKey1 should be in cache")
	}
	if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey2); err != nil {
		t.Fatal("cacheKey2 should be in cache")
	}
	if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey3); err != nil {
		t.Fatal("cacheKey3 should be in cache")
	}

	// Expire by URL (will delete all signature cache entries since keys are hashed)
	msg := SignatureCacheExpirationMessage{
		OriginID: "origin-123",
		URL:      "http://example.com/api/test",
		Method:   "GET",
	}
	config := SignatureCacheExpirationConfig{
		Enabled:       true,
		NormalizeURL:  true,
		NormalizePath: true,
		DefaultMethod: "GET",
	}

	err := ExpireSignatureCache(context.Background(), mgr, msg, config)
	if err != nil {
		t.Fatalf("ExpireSignatureCache failed: %v", err)
	}

	// Verify all signature cache entries are expired (URL-based expiration deletes all)
	// This is expected behavior since signature cache keys are hashed and we can't match by URL
	if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey1); err == nil {
		t.Error("All signature cache entries should be expired (URL-based expiration limitation)")
	} else {
		t.Logf("✓ cacheKey1 expired (URL-based expiration deletes all)")
	}
	if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey2); err == nil {
		t.Error("All signature cache entries should be expired (URL-based expiration limitation)")
	} else {
		t.Logf("✓ cacheKey2 expired (URL-based expiration deletes all)")
	}
	if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey3); err == nil {
		t.Error("All signature cache entries should be expired (URL-based expiration limitation)")
	} else {
		t.Logf("✓ cacheKey3 expired (URL-based expiration deletes all)")
	}
}

// TestNormalizeURLForSignatureCache tests URL normalization
func TestNormalizeURLForSignatureCache(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		config   SignatureCacheExpirationConfig
		expected string
	}{
		{
			name:   "normalize query params",
			rawURL: "http://example.com/api/users?page=1&limit=10",
			config: SignatureCacheExpirationConfig{
				NormalizeURL:  true,
				NormalizePath: false,
			},
			expected: "http://example.com/api/users",
		},
		{
			name:   "normalize trailing slash",
			rawURL: "http://example.com/api/users/",
			config: SignatureCacheExpirationConfig{
				NormalizeURL:  false,
				NormalizePath: true,
			},
			expected: "http://example.com/api/users",
		},
		{
			name:   "normalize both",
			rawURL: "http://example.com/api/users/?page=1",
			config: SignatureCacheExpirationConfig{
				NormalizeURL:  true,
				NormalizePath: true,
			},
			expected: "http://example.com/api/users",
		},
		{
			name:   "no normalization",
			rawURL: "http://example.com/api/users?page=1",
			config: SignatureCacheExpirationConfig{
				NormalizeURL:  false,
				NormalizePath: false,
			},
			expected: "http://example.com/api/users?page=1",
		},
		{
			name:   "path only",
			rawURL: "/api/users?page=1",
			config: SignatureCacheExpirationConfig{
				NormalizeURL:  true,
				NormalizePath: true,
			},
			expected: "/api/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeURLForSignatureCache(tt.rawURL, tt.config)
			if result != tt.expected {
				t.Errorf("normalizeURLForSignatureCache() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestHandleMessage_SignatureCacheExpiration tests message handling
func TestHandleMessage_SignatureCacheExpiration(t *testing.T) {
	mockCache := NewMockKVStore()
	testMessenger := NewTestMessengerForSignatureCacheExpiration()
	defer testMessenger.Close()

	mgr := &mockManagerWithCacheForTest{
		cache: &mockCacheWithListKeysForSignature{MockKVStore: mockCache},
	}

	mgrWithMessenger := &mockManagerWithMessengerForTest{
		mockManagerWithCacheForTest: mgr,
		messenger:                   testMessenger,
	}

	// Cache a signature-verified response
	cacheKey := "test-cache-key"
	cachedData := []byte(`{"status_code":200,"body":"test"}`)
	mockCache.Put(context.Background(), signatureCachePrefix, cacheKey, bytes.NewReader(cachedData))

	// Start subscriber with unique topic per test to avoid sync.Once conflicts
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use unique topic to avoid sync.Once conflicts between tests
	topic := "test_topic_signature_cache_" + t.Name()
	config := SignatureCacheExpirationConfig{
		Enabled:       true,
		NormalizeURL:  true,
		NormalizePath: true,
		DefaultMethod: "GET",
	}

	// Reset the sync.Once for testing
	ResetSignatureCacheExpirationSubscriber()

	err := StartSignatureCacheExpirationSubscriber(ctx, mgrWithMessenger, topic, config)
	if err != nil {
		t.Fatalf("Failed to start subscriber: %v", err)
	}

	// Wait for subscriber to be ready by checking if messenger has subscriber
	// The test messenger subscribes synchronously, so we just need a small delay
	time.Sleep(10 * time.Millisecond)

	// Send message with exact cache key (array format)
	batch := SignatureCacheExpirationBatch{
		Updates: []SignatureCacheExpirationMessage{{
			OriginID: "origin-123",
			CacheKey: cacheKey,
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
		if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey); err != nil {
			// Cache is expired, test passed
			return
		}
	}

	// Verify cache is expired
	if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey); err == nil {
		t.Error("Signature cache should be expired")
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
