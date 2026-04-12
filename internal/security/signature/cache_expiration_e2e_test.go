package signature

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

// TestSignatureCacheExpiration_EndToEnd tests the complete flow of signature cache expiration via message bus
func TestSignatureCacheExpiration_EndToEnd(t *testing.T) {
	// Create test messenger
	testMessenger := NewTestMessengerForSignatureCacheExpiration()
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
	mockCacheWithListKeys := &mockCacheWithListKeysForSignature{
		MockKVStore: mockCache,
	}

	// Override GetCache to return mock cache
	mgrWithCache := &mockManagerWithCache{
		mockManagerWithMessenger: mgr,
		cache:                     mockCacheWithListKeys,
	}

	// Step 1: Cache multiple signature-verified responses
	t.Run("Step 1: Cache signature-verified responses", func(t *testing.T) {
		// Response 1: Different signature
		cacheKey1 := "sig-cache-key-1"
		cachedData1 := []byte(`{"status_code":200,"body":"response1"}`)
		mockCache.Put(context.Background(), signatureCachePrefix, cacheKey1, bytes.NewReader(cachedData1))

		// Response 2: Different signature
		cacheKey2 := "sig-cache-key-2"
		cachedData2 := []byte(`{"status_code":200,"body":"response2"}`)
		mockCache.Put(context.Background(), signatureCachePrefix, cacheKey2, bytes.NewReader(cachedData2))

		// Response 3: Different URL (should not be expired with exact key)
		cacheKey3 := "sig-cache-key-3"
		cachedData3 := []byte(`{"status_code":200,"body":"response3"}`)
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

		t.Logf("✓ Cached 3 signature-verified responses")
		t.Logf("  cacheKey1: %s", cacheKey1)
		t.Logf("  cacheKey2: %s", cacheKey2)
		t.Logf("  cacheKey3: %s", cacheKey3)
	})

	// Step 2: Start the cache expiration subscriber
	t.Run("Step 2: Start cache expiration subscriber", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		topic := "signature_cache_expiration"
		config := SignatureCacheExpirationConfig{
			Enabled:       true,
			NormalizeURL:  true,
			NormalizePath: true,
			DefaultMethod: "GET",
		}

		err := StartSignatureCacheExpirationSubscriber(ctx, mgrWithCache, topic, config)
		if err != nil {
			t.Fatalf("Failed to start cache expiration subscriber: %v", err)
		}

		// Give subscriber time to initialize
		time.Sleep(50 * time.Millisecond)

		t.Logf("✓ Cache expiration subscriber started on topic: %s", topic)
	})

	// Step 3: Test exact cache key expiration
	t.Run("Step 3: Test exact cache key expiration", func(t *testing.T) {
		ctx := context.Background()
		topic := "signature_cache_expiration"

		// Send expiration message with exact cache key
		err := testMessenger.SendSignatureCacheExpirationMessage(ctx, topic, "origin-123", "", "", "sig-cache-key-1", "")
		if err != nil {
			t.Fatalf("Failed to send expiration message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		// Verify exact cache key is expired
		if _, err := mockCache.Get(context.Background(), signatureCachePrefix, "sig-cache-key-1"); err == nil {
			t.Error("Exact cache key should be expired")
		} else {
			t.Logf("✓ Exact cache key expired: sig-cache-key-1")
		}

		// Verify other keys are NOT expired
		if _, err := mockCache.Get(context.Background(), signatureCachePrefix, "sig-cache-key-2"); err != nil {
			t.Error("cacheKey2 should NOT be expired")
		} else {
			t.Logf("✓ cacheKey2 still in cache")
		}

		if _, err := mockCache.Get(context.Background(), signatureCachePrefix, "sig-cache-key-3"); err != nil {
			t.Error("cacheKey3 should NOT be expired")
		} else {
			t.Logf("✓ cacheKey3 still in cache")
		}
	})

	// Step 4: Test URL-based expiration (will delete all signature cache entries)
	t.Run("Step 4: Test URL-based expiration", func(t *testing.T) {
		ctx := context.Background()
		topic := "signature_cache_expiration"

		// Send expiration message for URL (will delete all signature cache entries)
		err := testMessenger.SendSignatureCacheExpirationMessage(ctx, topic, "origin-123", "http://example.com/api/test", "GET", "", "")
		if err != nil {
			t.Fatalf("Failed to send expiration message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		// Verify all signature cache entries are expired (URL-based expiration limitation)
		// This is expected behavior since signature cache keys are hashed and we can't match by URL
		if _, err := mockCache.Get(context.Background(), signatureCachePrefix, "sig-cache-key-2"); err == nil {
			t.Error("All signature cache entries should be expired (URL-based expiration limitation)")
		} else {
			t.Logf("✓ cacheKey2 expired (URL-based expiration deletes all)")
		}

		if _, err := mockCache.Get(context.Background(), signatureCachePrefix, "sig-cache-key-3"); err == nil {
			t.Error("All signature cache entries should be expired (URL-based expiration limitation)")
		} else {
			t.Logf("✓ cacheKey3 expired (URL-based expiration deletes all)")
		}
	})

	// Step 5: Test message with params only
	t.Run("Step 5: Test message with params only", func(t *testing.T) {
		// Cache a new response
		cacheKey := "sig-cache-key-params"
		cachedData := []byte(`{"status_code":200,"body":"params"}`)
		mockCache.Put(context.Background(), signatureCachePrefix, cacheKey, bytes.NewReader(cachedData))

		// Verify it's cached
		if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey); err != nil {
			t.Fatal("Response should be in cache")
		}

		// Send expiration message with array format
		ctx := context.Background()
		topic := "signature_cache_expiration"

		err := testMessenger.SendSignatureCacheExpirationMessage(ctx, topic, "origin-123", "", "GET", cacheKey, "")
		if err != nil {
			t.Fatalf("Failed to send expiration message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		// Verify cache is expired
		if _, err := mockCache.Get(context.Background(), signatureCachePrefix, cacheKey); err == nil {
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

