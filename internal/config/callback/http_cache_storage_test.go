package callback

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// mockCacher implements cacher.Cacher for testing
type mockCacher struct {
	store map[string][]byte
	ttl   map[string]time.Time
	mu    sync.RWMutex
}

func newMockCacher() *mockCacher {
	return &mockCacher{
		store: make(map[string][]byte),
		ttl:   make(map[string]time.Time),
	}
}

func (m *mockCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if data, exists := m.store[key]; exists {
		if ttl, hasTTL := m.ttl[key]; hasTTL && time.Now().After(ttl) {
			m.mu.RUnlock()
			m.mu.Lock()
			delete(m.store, key)
			delete(m.ttl, key)
			m.mu.Unlock()
			m.mu.RLock()
			return nil, cacher.ErrNotFound
		}
		return bytes.NewReader(data), nil
	}
	return nil, cacher.ErrNotFound
}

func (m *mockCacher) ListKeys(ctx context.Context, cType string, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for key := range m.store {
		if prefix == "" || (len(key) >= len(prefix) && key[:len(prefix)] == prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *mockCacher) Put(ctx context.Context, cType string, key string, data io.Reader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	bytes, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	m.store[key] = bytes
	return nil
}

func (m *mockCacher) PutWithExpires(ctx context.Context, cType string, key string, data io.Reader, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	bytes, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	m.store[key] = bytes
	if ttl > 0 {
		m.ttl[key] = time.Now().Add(ttl)
	}
	return nil
}

func (m *mockCacher) Delete(ctx context.Context, cType string, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, key)
	delete(m.ttl, key)
	return nil
}

func (m *mockCacher) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Simple implementation - delete all
	m.store = make(map[string][]byte)
	m.ttl = make(map[string]time.Time)
	return nil
}

func (m *mockCacher) Increment(ctx context.Context, cType string, key string, delta int64) (int64, error) {
	return 0, nil
}

func (m *mockCacher) IncrementWithExpires(ctx context.Context, cType string, key string, delta int64, ttl time.Duration) (int64, error) {
	return 0, nil
}

func (m *mockCacher) Driver() string {
	return "mock"
}

func (m *mockCacher) Close() error {
	return nil
}

func TestHTTPCallbackCache(t *testing.T) {
	l2Cache := newMockCacher()
	l3Cache := newMockCacher()
	parser := NewHTTPCacheParser(60*time.Second, 300*time.Second)
	httpCache := NewHTTPCallbackCache(l2Cache, l3Cache, parser, 1024*1024)
	ctx := context.Background()

	t.Run("cache miss returns false", func(t *testing.T) {
		cached, found, err := httpCache.Get(ctx, "nonexistent")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if found {
			t.Error("expected not found")
		}
		if cached != nil {
			t.Error("expected nil cached response")
		}
	})

	t.Run("put and get from L2 cache (small object)", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			ETag:                 "test-etag",
			LastModified:         now.Add(-1 * time.Hour),
			MaxAge:               60 * time.Second,
			StaleWhileRevalidate: 120 * time.Second,
			StaleIfError:         300 * time.Second,
		}
		parser.calculateExpiration(metadata, now)

		data := map[string]any{"test": "data"}
		headers := make(map[string][]string)
		headers["Content-Type"] = []string{"application/json"}

		err := httpCache.Put(ctx, "test-key", data, metadata, headers, http.StatusOK, 512) // < 1MB, goes to L2
		if err != nil {
			t.Fatalf("failed to put in cache: %v", err)
		}

		cached, found, err := httpCache.Get(ctx, "test-key")
		if err != nil {
			t.Fatalf("failed to get from cache: %v", err)
		}
		if !found {
			t.Fatal("expected found")
		}
		if cached == nil {
			t.Fatal("expected non-nil cached response")
		}
		if cached.ETag != "test-etag" {
			t.Errorf("expected ETag=test-etag, got %q", cached.ETag)
		}
		if cached.Tier != "l2" {
			t.Errorf("expected tier=l2, got %q", cached.Tier)
		}
		if cached.Data["test"] != "data" {
			t.Errorf("expected test=data, got %v", cached.Data["test"])
		}
	})

	t.Run("put and get from L3 cache (large object)", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			MaxAge:               60 * time.Second,
			StaleWhileRevalidate: 120 * time.Second,
			StaleIfError:         300 * time.Second,
		}
		parser.calculateExpiration(metadata, now)

		data := map[string]any{"large": "data"}
		headers := make(map[string][]string)

		// 2MB object should go to L3
		err := httpCache.Put(ctx, "large-key", data, metadata, headers, http.StatusOK, 2*1024*1024)
		if err != nil {
			t.Fatalf("failed to put in cache: %v", err)
		}

		cached, found, err := httpCache.Get(ctx, "large-key")
		if err != nil {
			t.Fatalf("failed to get from cache: %v", err)
		}
		if !found {
			t.Fatal("expected found")
		}
		if cached.Tier != "l3" {
			t.Errorf("expected tier=l3, got %q", cached.Tier)
		}
	})

	t.Run("cache state - fresh", func(t *testing.T) {
		now := time.Now()
		cached := &HTTPCachedCallbackResponse{
			ExpiresAt: now.Add(60 * time.Second),
			StaleAt:   now.Add(180 * time.Second),
			MaxStaleAt: now.Add(360 * time.Second),
		}

		if !cached.IsFresh(now) {
			t.Error("expected fresh")
		}

		state := cached.GetState(now)
		if state != StateFresh {
			t.Errorf("expected StateFresh, got %v", state)
		}
	})

	t.Run("cache state - stale", func(t *testing.T) {
		now := time.Now()
		cached := &HTTPCachedCallbackResponse{
			ExpiresAt: now.Add(-30 * time.Second),
			StaleAt:   now.Add(90 * time.Second),
			MaxStaleAt: now.Add(270 * time.Second),
		}

		if cached.IsFresh(now) {
			t.Error("expected not fresh")
		}

		if !cached.CanServeStale(now, false) {
			t.Error("expected can serve stale")
		}

		state := cached.GetState(now)
		if state != StateStale {
			t.Errorf("expected StateStale, got %v", state)
		}
	})

	t.Run("cache state - stale-error", func(t *testing.T) {
		now := time.Now()
		cached := &HTTPCachedCallbackResponse{
			ExpiresAt: now.Add(-120 * time.Second),
			StaleAt:   now.Add(-30 * time.Second),
			MaxStaleAt: now.Add(150 * time.Second),
		}

		if !cached.CanServeStale(now, true) {
			t.Error("expected can serve stale-error")
		}

		state := cached.GetState(now)
		if state != StateStaleError {
			t.Errorf("expected StateStaleError, got %v", state)
		}
	})

	t.Run("cache expiration", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			MaxAge: 100 * time.Millisecond,
		}
		parser.calculateExpiration(metadata, now)

		data := map[string]any{"expired": true}
		headers := make(map[string][]string)

		err := httpCache.Put(ctx, "expiring-key", data, metadata, headers, http.StatusOK, 512)
		if err != nil {
			t.Fatalf("failed to put in cache: %v", err)
		}

		// Should be found immediately
		_, found, _ := httpCache.Get(ctx, "expiring-key")
		if !found {
			t.Error("expected found immediately after put")
		}

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Should not be found after expiration
		_, found, _ = httpCache.Get(ctx, "expiring-key")
		if found {
			t.Error("expected not found after expiration")
		}
	})

	t.Run("cache invalidation", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			MaxAge: 60 * time.Second,
		}
		parser.calculateExpiration(metadata, now)

		data := map[string]any{"test": "data"}
		headers := make(map[string][]string)

		err := httpCache.Put(ctx, "to-invalidate", data, metadata, headers, http.StatusOK, 512)
		if err != nil {
			t.Fatalf("failed to put in cache: %v", err)
		}

		// Verify it exists
		_, found, _ := httpCache.Get(ctx, "to-invalidate")
		if !found {
			t.Fatal("expected to find entry before invalidation")
		}

		// Invalidate
		err = httpCache.Invalidate(ctx, "to-invalidate")
		if err != nil {
			t.Fatalf("failed to invalidate: %v", err)
		}

		// Should not be found after invalidation
		_, found, _ = httpCache.Get(ctx, "to-invalidate")
		if found {
			t.Error("expected not found after invalidation")
		}
	})

	t.Run("revalidation tracking", func(t *testing.T) {
		if httpCache.IsRevalidating("test-key") {
			t.Error("expected not revalidating initially")
		}

		httpCache.SetRevalidating("test-key")
		if !httpCache.IsRevalidating("test-key") {
			t.Error("expected revalidating after SetRevalidating")
		}

		httpCache.ClearRevalidating("test-key")
		if httpCache.IsRevalidating("test-key") {
			t.Error("expected not revalidating after ClearRevalidating")
		}
	})

	t.Run("circuit breaker integration", func(t *testing.T) {
		cb := httpCache.GetCircuitBreaker("test-circuit")
		if cb == nil {
			t.Fatal("expected circuit breaker")
		}
		if cb.GetState() != circuitStateClosed {
			t.Errorf("expected closed state, got %v", cb.GetState())
		}

		// Same key should return same circuit breaker
		cb2 := httpCache.GetCircuitBreaker("test-circuit")
		if cb != cb2 {
			t.Error("expected same circuit breaker instance")
		}
	})

	t.Run("fallback from L2 to L3", func(t *testing.T) {
		// Put in L3 only
		now := time.Now()
		metadata := &CacheMetadata{
			MaxAge: 60 * time.Second,
		}
		parser.calculateExpiration(metadata, now)

		data := map[string]any{"l3": "data"}
		headers := make(map[string][]string)

		// Manually put in L3
		cached := HTTPCachedCallbackResponse{
			Data:      data,
			Headers:   headers,
			ExpiresAt: metadata.ExpiresAt,
			StaleAt:   metadata.StaleAt,
			MaxStaleAt: metadata.MaxStaleAt,
			Size:      2 * 1024 * 1024,
			Tier:      "l3",
		}

		jsonData, _ := json.Marshal(cached)
		l3Cache.PutWithExpires(ctx, callbackCacheType, "l3-key", bytes.NewReader(jsonData), 60*time.Second)

		// Get should find it in L3
		cachedResp, found, err := httpCache.Get(ctx, "l3-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Error("expected found in L3")
		}
		if cachedResp.Tier != "l3" {
			t.Errorf("expected tier=l3, got %q", cachedResp.Tier)
		}
	})
}

