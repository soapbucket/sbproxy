package responsecache

import (
	"bytes"
	"context"
	"encoding/gob"
	"github.com/soapbucket/sbproxy/internal/engine/handler"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// benchCtxKey is a custom type for context keys to avoid SA1029
type benchCtxKey string

// BenchmarkProxyServeHTTP benchmarks the main proxy ServeHTTP method
func BenchmarkProxyServeHTTP(b *testing.B) {
	b.ReportAllocs()
	// Create test request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")

	// Create mock response writer
	rw := httptest.NewRecorder()

	// Create proxy with mock transport
	proxy := handler.NewProxy(
		time.Second,      // flushInterval
		time.Second*5,    // retryDelay
		3,                // maxRetryCount
		nil,              // modFn
		nil,              // errFn
		&mockTransport{}, // transport
		false,            // debug
	)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			proxy.ServeHTTP(rw, req)
		}
	})
}

// BenchmarkCachedResponseGet benchmarks getting cached responses
func BenchmarkCachedResponseGet(b *testing.B) {
	b.ReportAllocs()
	// Create mock cacher
	cacher := &mockCacher{}

	// Create test URL
	testURL, _ := url.Parse("http://example.com/test")

	// Create test response
	testResp := &CachedResponse{
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte("test response body"),
		Size:    18,
	}

	// Save response to cache
	SaveCachedResponse(cacher, testURL, testResp, time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetCachedResponse(cacher, testURL)
	}
}

// BenchmarkCachedResponseSave benchmarks saving cached responses
func BenchmarkCachedResponseSave(b *testing.B) {
	b.ReportAllocs()
	// Create mock cacher
	cacher := &mockCacher{}

	// Create test URL
	testURL, _ := url.Parse("http://example.com/test")

	// Create test response
	testResp := &CachedResponse{
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte("test response body"),
		Size:    18,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SaveCachedResponse(cacher, testURL, testResp, time.Minute)
	}
}

// BenchmarkGobEncoding benchmarks gob encoding of cached responses
func BenchmarkGobEncoding(b *testing.B) {
	b.ReportAllocs()
	testResp := &CachedResponse{
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte("test response body for encoding benchmark"),
		Size:    42,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		encoder := gob.NewEncoder(&buf)
		_ = encoder.Encode(testResp)
	}
}

// BenchmarkGobDecoding benchmarks gob decoding of cached responses
func BenchmarkGobDecoding(b *testing.B) {
	b.ReportAllocs()
	testResp := &CachedResponse{
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte("test response body for decoding benchmark"),
		Size:    45,
	}

	// Pre-encode the response
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	_ = encoder.Encode(testResp)
	encodedData := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var decodedResp CachedResponse
		decoder := gob.NewDecoder(bytes.NewReader(encodedData))
		_ = decoder.Decode(&decodedResp)
	}
}

// BenchmarkChunkCacher benchmarks chunk caching operations
func BenchmarkChunkCacher(b *testing.B) {
	b.ReportAllocs()
	cacher := &mockCacher{}
	// Create test chunk data
	chunkData := []byte("test chunk data for benchmarking")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Simulate chunk operations
			_ = cacher.Put(context.Background(), "cacher", "test-key", bytes.NewReader(chunkData))
			_, _ = cacher.Get(context.Background(), "cacher", "test-key")
		}
	})
}

// BenchmarkEchoHandler benchmarks the echo handler
func BenchmarkEchoHandler(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/echo", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Content-Type", "application/json")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Create a new response writer for each iteration to avoid concurrent map writes
			rw := httptest.NewRecorder()
			handler.EchoHandler(rw, req)
		}
	})
}

// BenchmarkRequestProcessing benchmarks request processing overhead
func BenchmarkRequestProcessing(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Encoding", "gzip")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate request processing
		_ = req.Method
		_ = req.URL.String()
		_ = req.Header.Get("User-Agent")
		_ = req.Header.Get("Accept")
		_ = len(req.Header)
	}
}

// BenchmarkResponseProcessing benchmarks response processing overhead
func BenchmarkResponseProcessing(b *testing.B) {
	b.ReportAllocs()
	headers := http.Header{
		"Content-Type":   []string{"text/html"},
		"Content-Length": []string{"1024"},
		"Cache-Control":  []string{"max-age=3600"},
		"ETag":           []string{"\"abc123\""},
	}

	body := []byte("test response body for processing benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate response processing
		_ = headers.Get("Content-Type")
		_ = headers.Get("Content-Length")
		_ = len(headers)
		_ = len(body)
	}
}

// BenchmarkCacheKeyGeneration benchmarks cache key generation
func BenchmarkCacheKeyGeneration(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/test?param1=value1&param2=value2", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate cache key (assuming this function exists)
		_ = req.Method + "|" + req.URL.String() + "|" + req.Header.Get("Accept")
	}
}

// BenchmarkHTTPHeaders benchmarks HTTP header operations
func BenchmarkHTTPHeaders(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cookie", "session=abc123; user=test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Header operations
		_ = req.Header.Get("User-Agent")
		_ = req.Header.Get("Accept")
		_ = req.Header.Get("Accept-Encoding")
		_ = req.Header.Get("Accept-Language")
		_ = req.Header.Get("Connection")
		_ = req.Header.Get("Cookie")
	}
}

// BenchmarkContextOperations benchmarks context operations
func BenchmarkContextOperations(b *testing.B) {
	b.ReportAllocs()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Set values in context
		ctx = context.WithValue(ctx, benchCtxKey("request_id"), "test-123")
		ctx = context.WithValue(ctx, benchCtxKey("user_id"), "user-456")
		ctx = context.WithValue(ctx, benchCtxKey("session_id"), "session-789")

		// Get values from context
		_ = ctx.Value(benchCtxKey("request_id"))
		_ = ctx.Value(benchCtxKey("user_id"))
		_ = ctx.Value(benchCtxKey("session_id"))
	}
}

// BenchmarkMemoryAllocations benchmarks memory allocations
func BenchmarkMemoryAllocations(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Allocate various data structures
		headers := make(http.Header)
		headers.Set("Content-Type", "text/html")
		headers.Set("Content-Length", "1024")

		body := make([]byte, 1024)
		for j := range body {
			body[j] = byte(i % 256)
		}

		response := &CachedResponse{
			Status:  200,
			Headers: headers,
			Body:    body,
			Size:    len(body),
		}

		_ = response
	}
}

// mockTransport implements http.RoundTripper for testing
type mockTransport struct{}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Return a mock response
	return &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}, nil
}

// mockCacher implements a simple in-memory cache for testing
type mockCacher struct {
	data map[string][]byte
	mu   sync.Mutex
}

func (m *mockCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	if data, exists := m.data[key]; exists {
		return bytes.NewReader(data), nil
	}
	return nil, cacher.ErrNotFound
}

func (m *mockCacher) Put(ctx context.Context, cType string, key string, value io.Reader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	data, err := io.ReadAll(value)
	if err != nil {
		return err
	}
	m.data[key] = data
	return nil
}

func (m *mockCacher) PutWithExpires(ctx context.Context, cType string, key string, value io.Reader, expires time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	data, err := io.ReadAll(value)
	if err != nil {
		return err
	}
	m.data[key] = data
	return nil
}

func (m *mockCacher) Close() error {
	return nil
}

func (m *mockCacher) Delete(ctx context.Context, cType string, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	delete(m.data, key)
	return nil
}

func (m *mockCacher) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	// Remove wildcard suffix for pattern matching (e.g., "GET:/api/users:*" -> "GET:/api/users:")
	patternPrefix := pattern
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		patternPrefix = pattern[:len(pattern)-1]
	}
	for key := range m.data {
		// Match prefix (for patterns like "GET:/api/users:*")
		if patternPrefix == "" || strings.HasPrefix(key, patternPrefix) {
			delete(m.data, key)
		}
	}
	return nil
}

func (m *mockCacher) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	var keys []string
	for key := range m.data {
		// Simple prefix matching for pattern
		if pattern == "" || strings.HasPrefix(key, pattern) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *mockCacher) Increment(ctx context.Context, cType string, key string, delta int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	// Simple increment implementation
	return 1, nil
}

func (m *mockCacher) IncrementWithExpires(ctx context.Context, cType string, key string, delta int64, expires time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	// Simple increment implementation
	return 1, nil
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
