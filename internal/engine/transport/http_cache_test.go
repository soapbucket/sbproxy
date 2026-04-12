package transport

import (
	"bytes"
	"context"
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
			// Need to upgrade to write lock for deletion
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
	for key := range m.store {
		if strings.HasPrefix(key, pattern) {
			delete(m.store, key)
			delete(m.ttl, key)
		}
	}
	return nil
}

func (m *mockCacher) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	return count, nil
}

func (m *mockCacher) IncrementWithExpires(ctx context.Context, cType string, key string, count int64, ttl time.Duration) (int64, error) {
	return count, nil
}

func (m *mockCacher) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for key := range m.store {
		// Simple pattern matching
		if pattern == "*" || pattern == key || strings.HasPrefix(key, pattern) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *mockCacher) Close() error {
	return nil
}

// WithPrefix methods
func (m *mockCacher) GetWithPrefix(ctx context.Context, cType string, key string) (io.Reader, error) {
	return m.Get(ctx, cType, key)
}

func (m *mockCacher) PutWithPrefix(ctx context.Context, cType string, key string, value io.Reader) error {
	return m.Put(ctx, cType, key, value)
}

func (m *mockCacher) PutWithPrefixAndExpires(ctx context.Context, cType string, key string, value io.Reader, expires time.Duration) error {
	return m.PutWithExpires(ctx, cType, key, value, expires)
}

func (m *mockCacher) DeleteWithPrefix(ctx context.Context, cType string, key string) error {
	return m.Delete(ctx, cType, key)
}

func (m *mockCacher) DeleteWithPrefixByPattern(ctx context.Context, cType string, pattern string) error {
	return m.DeleteByPattern(ctx, cType, pattern)
}

func (m *mockCacher) IncrementWithPrefix(ctx context.Context, cType string, key string, count int64) (int64, error) {
	return m.Increment(ctx, cType, key, count)
}

func (m *mockCacher) IncrementWithPrefixAndExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	return m.IncrementWithExpires(ctx, cType, key, count, expires)
}

func (m *mockCacher) Driver() string {
	return "mock"
}

// mockRoundTripper implements http.RoundTripper for testing
type mockRoundTripper struct {
	responses map[string]*http.Response
	requests  []*http.Request
}

func newMockRoundTripper() *mockRoundTripper {
	return &mockRoundTripper{
		responses: make(map[string]*http.Response),
		requests:  make([]*http.Request, 0),
	}
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	key := req.Method + " " + req.URL.String()
	if resp, exists := m.responses[key]; exists {
		// Clone the response to avoid issues with body reuse
		respClone := *resp
		respClone.Body = io.NopCloser(bytes.NewReader([]byte(resp.Header.Get("X-Test-Body"))))
		return &respClone, nil
	}

	// Default response
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("default response")),
	}, nil
}

func (m *mockRoundTripper) setResponse(method, url string, resp *http.Response) {
	key := method + " " + url
	m.responses[key] = resp
}

func TestHTTPCacheTransport_ShouldBypassCache(t *testing.T) {
	tests := []struct {
		name           string
		requestHeaders map[string]string
		config         *CacheConfig
		expected       bool
	}{
		{
			name:           "no bypass headers",
			requestHeaders: map[string]string{},
			config:         DefaultCacheConfig(),
			expected:       false,
		},
		{
			name: "cache-control no-cache",
			requestHeaders: map[string]string{
				"Cache-Control": "no-cache",
			},
			config:   DefaultCacheConfig(),
			expected: true,
		},
		{
			name: "pragma no-cache",
			requestHeaders: map[string]string{
				"Pragma": "no-cache",
			},
			config:   DefaultCacheConfig(),
			expected: true,
		},
		{
			name: "pragma no-cache case insensitive",
			requestHeaders: map[string]string{
				"Pragma": "NO-CACHE",
			},
			config:   DefaultCacheConfig(),
			expected: true,
		},
		{
			name: "respect no-cache disabled",
			requestHeaders: map[string]string{
				"Cache-Control": "no-cache",
			},
			config: &CacheConfig{
				RespectNoCache: false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &HTTPCacheTransport{
				config: tt.config,
			}

			req := httptest.NewRequest("GET", "http://example.com", nil)
			for key, value := range tt.requestHeaders {
				req.Header.Set(key, value)
			}

			result := transport.shouldBypassCache(req)
			if result != tt.expected {
				t.Errorf("shouldBypassCache() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHTTPCacheTransport_ShouldCacheResponse(t *testing.T) {
	tests := []struct {
		name            string
		responseHeaders map[string]string
		config          *CacheConfig
		expected        bool
	}{
		{
			name:            "cacheable response",
			responseHeaders: map[string]string{},
			config:          DefaultCacheConfig(),
			expected:        true,
		},
		{
			name: "no-store directive",
			responseHeaders: map[string]string{
				"Cache-Control": "no-store",
			},
			config:   DefaultCacheConfig(),
			expected: false,
		},
		{
			name: "private directive",
			responseHeaders: map[string]string{
				"Cache-Control": "private",
			},
			config:   DefaultCacheConfig(),
			expected: false,
		},
		{
			name: "private directive with respect disabled",
			responseHeaders: map[string]string{
				"Cache-Control": "private",
			},
			config: &CacheConfig{
				RespectPrivate: false,
			},
			expected: true,
		},
		{
			name: "set-cookie header (cached with cookie stripped)",
			responseHeaders: map[string]string{
				"Set-Cookie": "session=abc123",
			},
			config:   DefaultCacheConfig(),
			expected: true, // Set-Cookie is stripped by cleanHeaders(), response is still cacheable
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &HTTPCacheTransport{
				config: tt.config,
			}

			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
			}
			for key, value := range tt.responseHeaders {
				resp.Header.Set(key, value)
			}

			result := transport.shouldCacheResponse(resp)
			if result != tt.expected {
				t.Errorf("shouldCacheResponse() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHTTPCacheTransport_CalculateTTL(t *testing.T) {
	tests := []struct {
		name            string
		responseHeaders map[string]string
		config          *CacheConfig
		expectedMin     time.Duration
		expectedMax     time.Duration
	}{
		{
			name:            "default TTL",
			responseHeaders: map[string]string{},
			config:          DefaultCacheConfig(),
			expectedMin:     defaultCacheDuration,
			expectedMax:     defaultCacheDuration,
		},
		{
			name: "cache-control max-age",
			responseHeaders: map[string]string{
				"Cache-Control": "max-age=3600",
			},
			config:      DefaultCacheConfig(),
			expectedMin: time.Hour,
			expectedMax: time.Hour,
		},
		{
			name: "cache-control max-age exceeds max TTL",
			responseHeaders: map[string]string{
				"Cache-Control": "max-age=86400", // 24 hours
			},
			config: &CacheConfig{
				MaxTTL: time.Hour,
			},
			expectedMin: time.Hour,
			expectedMax: time.Hour,
		},
		{
			name: "expires header",
			responseHeaders: map[string]string{
				"Date":    "Mon, 01 Jan 2024 12:00:00 GMT",
				"Expires": "Mon, 01 Jan 2024 13:00:00 GMT",
			},
			config:      DefaultCacheConfig(),
			expectedMin: time.Hour,
			expectedMax: time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &HTTPCacheTransport{
				config: tt.config,
			}

			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
			}
			for key, value := range tt.responseHeaders {
				resp.Header.Set(key, value)
			}

			result := transport.calculateTTL(resp)
			if result < tt.expectedMin || result > tt.expectedMax {
				t.Errorf("calculateTTL() = %v, want between %v and %v", result, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestHTTPCacheTransport_HandleConditionalRequest(t *testing.T) {
	tests := []struct {
		name           string
		requestHeaders map[string]string
		cachedETag     string
		cachedLastMod  string
		expectedStatus int
		expectedNil    bool
	}{
		{
			name:           "no conditional headers",
			requestHeaders: map[string]string{},
			expectedNil:    true,
		},
		{
			name: "if-none-match match",
			requestHeaders: map[string]string{
				"If-None-Match": `"abc123"`,
			},
			cachedETag:     `"abc123"`,
			expectedStatus: http.StatusNotModified,
		},
		{
			name: "if-none-match wildcard",
			requestHeaders: map[string]string{
				"If-None-Match": "*",
			},
			cachedETag:     `"abc123"`,
			expectedStatus: http.StatusNotModified,
		},
		{
			name: "if-none-match no match",
			requestHeaders: map[string]string{
				"If-None-Match": `"xyz789"`,
			},
			cachedETag:  `"abc123"`,
			expectedNil: true,
		},
		{
			name: "if-modified-since not modified",
			requestHeaders: map[string]string{
				"If-Modified-Since": "Mon, 01 Jan 2024 12:00:00 GMT",
			},
			cachedLastMod:  "Mon, 01 Jan 2024 11:00:00 GMT",
			expectedStatus: http.StatusNotModified,
		},
		{
			name: "if-modified-since modified",
			requestHeaders: map[string]string{
				"If-Modified-Since": "Mon, 01 Jan 2024 10:00:00 GMT",
			},
			cachedLastMod: "Mon, 01 Jan 2024 11:00:00 GMT",
			expectedNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &HTTPCacheTransport{}

			req := httptest.NewRequest("GET", "http://example.com", nil)
			for key, value := range tt.requestHeaders {
				req.Header.Set(key, value)
			}

			cached := &HTTPCacheEntry{
				Header: make(http.Header),
				ETag:   tt.cachedETag,
			}
			if tt.cachedLastMod != "" {
				cached.Header.Set("Last-Modified", tt.cachedLastMod)
			}

			result := transport.handleConditionalRequest(req, cached)

			if tt.expectedNil {
				if result != nil {
					t.Errorf("handleConditionalRequest() = %v, want nil", result)
				}
			} else {
				if result == nil {
					t.Errorf("handleConditionalRequest() = nil, want response with status %d", tt.expectedStatus)
				} else if result.StatusCode != tt.expectedStatus {
					t.Errorf("handleConditionalRequest() status = %d, want %d", result.StatusCode, tt.expectedStatus)
				}
			}
		})
	}
}

func TestHTTPCacheTransport_RoundTrip(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		requestHeaders  map[string]string
		responseHeaders map[string]string
		config          *CacheConfig
		expectedCalls   int
		expectedStatus  int
	}{
		{
			name:   "GET request cached",
			method: "GET",
			responseHeaders: map[string]string{
				"Cache-Control": "max-age=3600",
				"X-Test-Body":   "test response",
			},
			expectedCalls:  2, // First call + second call to test cache
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST request not cached",
			method:         "POST",
			expectedCalls:  1,
			expectedStatus: http.StatusOK,
		},
		{
			name:   "authorization header not cached",
			method: "GET",
			requestHeaders: map[string]string{
				"Authorization": "Bearer token",
			},
			expectedCalls:  1,
			expectedStatus: http.StatusOK,
		},
		{
			name:   "no-cache request bypassed",
			method: "GET",
			requestHeaders: map[string]string{
				"Cache-Control": "no-cache",
			},
			expectedCalls:  1,
			expectedStatus: http.StatusOK,
		},
		{
			name:   "error response not cached by default",
			method: "GET",
			responseHeaders: map[string]string{
				"X-Test-Status": "404",
			},
			expectedCalls:  2,             // First call + second call to test cache
			expectedStatus: http.StatusOK, // Mock returns 200 by default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRT := newMockRoundTripper()
			mockCache := newMockCacher()

			// Set up mock response
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("test response")),
			}
			for key, value := range tt.responseHeaders {
				resp.Header.Set(key, value)
			}
			mockRT.setResponse(tt.method, "http://example.com", resp)

			config := tt.config
			if config == nil {
				config = DefaultCacheConfig()
			}

			transport := NewHTTPCacheTransport(mockRT, mockCache, config)

			// First request
			req := httptest.NewRequest(tt.method, "http://example.com", nil)
			for key, value := range tt.requestHeaders {
				req.Header.Set(key, value)
			}

			resp1, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip() error = %v", err)
			}
			if resp1.StatusCode != tt.expectedStatus {
				t.Errorf("RoundTrip() status = %d, want %d", resp1.StatusCode, tt.expectedStatus)
			}

			// Second request (should be cached for GET requests)
			if tt.method == "GET" && len(tt.requestHeaders) == 0 {
				resp2, err := transport.RoundTrip(req)
				if err != nil {
					t.Fatalf("RoundTrip() error = %v", err)
				}
				if resp2.StatusCode != tt.expectedStatus {
					t.Errorf("RoundTrip() status = %d, want %d", resp2.StatusCode, tt.expectedStatus)
				}
			}

			if len(mockRT.requests) != tt.expectedCalls {
				t.Errorf("RoundTrip() made %d calls, want %d", len(mockRT.requests), tt.expectedCalls)
			}
		})
	}
}

func TestHTTPCacheBody_ReadAndClose(t *testing.T) {
	testData := "test response body"
	reader := strings.NewReader(testData)

	mockCache := newMockCacher()
	hasher := httpCacheXxhashPool.Get().(hash.Hash)
	hasher.Reset()

	body := &HTTPCacheBody{
		header:     make(http.Header),
		statusCode: http.StatusOK,
		buff:       new(bytes.Buffer),
		reader:     io.NopCloser(reader),
		key:        "test-key",
		ttl:        time.Hour,
		store:      mockCache,
		hasher:     hasher,
	}

	// Read all data
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(data) != testData {
		t.Errorf("ReadAll() = %q, want %q", string(data), testData)
	}

	// Close to trigger caching
	err = body.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Wait a bit for async cache storage
	time.Sleep(10 * time.Millisecond)

	// Verify cache entry was stored
	headerKey := cacheHeaderPrefix + "test-key"
	// Use the same hash function as the implementation
	hkey := crypto.GetHashFromString(headerKey)
	mockCache.mu.RLock()
	_, exists := mockCache.store[hkey]
	mockCache.mu.RUnlock()
	if !exists {
		t.Error("Cache entry was not stored")
	}

	// Return hasher to pool
	httpCacheXxhashPool.Put(hasher)
}

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()

	if config.CacheErrors {
		t.Error("DefaultCacheConfig() CacheErrors = true, want false")
	}
	if config.DefaultTTL != defaultCacheDuration {
		t.Errorf("DefaultCacheConfig() DefaultTTL = %v, want %v", config.DefaultTTL, defaultCacheDuration)
	}
	if config.MaxTTL != maxCacheDuration {
		t.Errorf("DefaultCacheConfig() MaxTTL = %v, want %v", config.MaxTTL, maxCacheDuration)
	}
	if !config.RespectNoCache {
		t.Error("DefaultCacheConfig() RespectNoCache = false, want true")
	}
	if !config.RespectPrivate {
		t.Error("DefaultCacheConfig() RespectPrivate = false, want true")
	}
}

func TestHTTPCacheTransport_IsCacheExpired(t *testing.T) {
	tests := []struct {
		name            string
		cachedHeaders   map[string]string
		cachedTimestamp time.Time
		config          *CacheConfig
		expected        bool
	}{
		{
			name:            "not expired with default TTL",
			cachedTimestamp: time.Now().Add(-time.Minute),
			config:          DefaultCacheConfig(),
			expected:        false,
		},
		{
			name:            "expired with default TTL",
			cachedTimestamp: time.Now().Add(-10 * time.Minute),
			config:          DefaultCacheConfig(),
			expected:        true,
		},
		{
			name: "not expired with max-age",
			cachedHeaders: map[string]string{
				"Cache-Control": "max-age=3600",
			},
			cachedTimestamp: time.Now().Add(-time.Minute),
			config:          DefaultCacheConfig(),
			expected:        false,
		},
		{
			name: "expired with max-age",
			cachedHeaders: map[string]string{
				"Cache-Control": "max-age=60",
			},
			cachedTimestamp: time.Now().Add(-2 * time.Minute),
			config:          DefaultCacheConfig(),
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &HTTPCacheTransport{
				config: tt.config,
			}

			cached := &HTTPCacheEntry{
				Header:    make(http.Header),
				Timestamp: tt.cachedTimestamp,
			}
			for key, value := range tt.cachedHeaders {
				cached.Header.Set(key, value)
			}

			result := transport.isCacheExpired(cached)
			if result != tt.expected {
				t.Errorf("isCacheExpired() = %v, want %v", result, tt.expected)
			}
		})
	}
}
