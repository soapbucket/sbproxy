package responsecache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// MockKVStore implements cacher.Cacher for testing
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
	if data, exists := m.data[key]; exists {
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
	m.data[key] = data
	return nil
}

func (m *MockKVStore) PutWithExpires(ctx context.Context, cType string, key string, value io.Reader, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := io.ReadAll(value)
	if err != nil {
		return err
	}
	m.data[key] = data
	return nil
}

func (m *MockKVStore) Delete(ctx context.Context, cType string, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *MockKVStore) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Parse pattern: {METHOD}:{URL}:*
	// Since cache keys are hashed, we need to regenerate keys from the pattern to match them
	parts := strings.Split(pattern, ":")
	if len(parts) < 2 {
		// Invalid pattern, try simple prefix matching
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
	
	method := parts[0]
	urlPart := strings.Join(parts[1:len(parts)-1], ":") // Rejoin URL parts (may contain colons)
	if len(parts) > 0 && parts[len(parts)-1] == "*" {
		// Remove the wildcard
		urlPart = strings.Join(parts[1:len(parts)-1], ":")
	}
	
	// Try to regenerate keys from the pattern
	// Create a test request to generate the cache key
	testReq, err := http.NewRequest(method, urlPart, nil)
	if err == nil {
		testReq = testReq.WithContext(ctx)
		
		// Generate keys for common vary header combinations
		// This handles the case where cache keys include vary headers (like Accept-Encoding)
		varyCombinations := []map[string]string{
			{"Accept-Encoding": "gzip"},
			{"Accept-Encoding": "br"},
			{"Accept-Encoding": "deflate"},
			{"Accept-Encoding": "identity"},
			{}, // No vary headers
		}
		
		keysToDelete := make(map[string]bool)
		
		// Generate keys for each vary combination
		for _, varyHeaders := range varyCombinations {
			testReqWithVary := testReq.Clone(ctx)
			for k, v := range varyHeaders {
				testReqWithVary.Header.Set(k, v)
			}
			key := httputil.GenerateCacheKey(testReqWithVary)
			keysToDelete[key] = true
		}
		
		// Delete all matching keys
		for key := range keysToDelete {
			if _, exists := m.data[key]; exists {
				delete(m.data, key)
			}
		}
	} else {
		// Fallback to simple prefix matching if URL parsing fails
		patternPrefix := pattern
		if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
			patternPrefix = pattern[:len(pattern)-1]
		}
		for key := range m.data {
			if patternPrefix == "" || (len(key) >= len(patternPrefix) && key[:len(patternPrefix)] == patternPrefix) {
				delete(m.data, key)
			}
		}
	}
	
	return nil
}

func (m *MockKVStore) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for key := range m.data {
		// Simple prefix matching for pattern
		if pattern == "" || (len(key) >= len(pattern) && key[:len(pattern)] == pattern) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *MockKVStore) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Simple implementation for testing
	if _, exists := m.data[key]; exists {
		// Try to parse as int64 and increment
		// For simplicity, just return the count
		return count, nil
	}
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

func TestCachedResponse_IsTooLarge(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		size     int
		expected bool
	}{
		{
			name:     "not too large",
			body:     []byte("hello"),
			size:     5,
			expected: false,
		},
		{
			name:     "too large",
			body:     []byte("hello"),
			size:     3,
			expected: true,
		},
		{
			name:     "empty body",
			body:     []byte{},
			size:     0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := &CachedResponse{
				Body: tt.body,
				Size: tt.size,
			}

			if cr.IsTooLarge() != tt.expected {
				t.Errorf("IsTooLarge() = %v, expected %v", cr.IsTooLarge(), tt.expected)
			}
		})
	}
}

func TestCachedResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	crw := NewCachedResponseWriter(w, 100)

	// Test Header()
	header := crw.Header()
	if header == nil {
		t.Error("Expected header to be non-nil")
	}

	// Test WriteHeader()
	crw.WriteHeader(http.StatusOK)
	if crw.status != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, crw.status)
	}

	// Test Write()
	data := []byte("test data")
	n, err := crw.Write(data)
	if err != nil {
		t.Errorf("Write() error = %v", err)
	}
	if n != len(data) {
		t.Errorf("Write() returned %d, expected %d", n, len(data))
	}

	// Test Flush()
	crw.Flush() // Should not panic

	// Test GetCachedResponse()
	cached := crw.GetCachedResponse()
	if cached == nil {
		t.Error("Expected cached response to be non-nil")
		return
	}
	if cached.Status != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, cached.Status)
		return
	}
	if !bytes.Equal(cached.Body, data) {
		t.Errorf("Expected body %v, got %v", data, cached.Body)
	}
}

func TestNewCachedResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	capacity := 1000

	crw := NewCachedResponseWriter(w, capacity)

	if crw.rw != w {
		t.Error("Expected rw to be set")
	}
	if crw.capacity != capacity {
		t.Errorf("Expected capacity %d, got %d", capacity, crw.capacity)
	}
}

func TestGetCachedResponse(t *testing.T) {
	store := NewMockKVStore()
	URL, _ := url.Parse("http://example.com/test")

	// Test with no cached response
	_, found := GetCachedResponse(store, URL)
	if found {
		t.Error("Expected no cached response to be found")
	}

	// Test with cached response
	cachedResp := &CachedResponse{
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/plain"}},
		Body:    []byte("test"),
		Size:    4,
	}

	// Save the response first
	err := SaveCachedResponse(store, URL, cachedResp, time.Hour)
	if err != nil {
		t.Fatalf("SaveCachedResponse() error = %v", err)
	}

	// Now try to get it
	resp, found := GetCachedResponse(store, URL)
	if !found {
		t.Error("Expected cached response to be found")
	}
	if resp.Status != cachedResp.Status {
		t.Errorf("Expected status %d, got %d", cachedResp.Status, resp.Status)
	}
}

func TestSaveCachedResponse(t *testing.T) {
	store := NewMockKVStore()
	URL, _ := url.Parse("http://example.com/test")

	cachedResp := &CachedResponse{
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/plain"}},
		Body:    []byte("test"),
		Size:    4,
	}

	err := SaveCachedResponse(store, URL, cachedResp, time.Hour)
	if err != nil {
		t.Errorf("SaveCachedResponse() error = %v", err)
	}

	// Verify it was saved
	_, found := GetCachedResponse(store, URL)
	if !found {
		t.Error("Expected cached response to be found after saving")
	}
}
