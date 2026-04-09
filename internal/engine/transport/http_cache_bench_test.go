package transport

import (
	"bytes"
	"context"
	"fmt"
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

// benchmarkCacher implements cacher.Cacher optimized for benchmarks
type benchmarkCacher struct {
	store map[string][]byte
	mu    sync.RWMutex
}

func newBenchmarkCacher() *benchmarkCacher {
	return &benchmarkCacher{
		store: make(map[string][]byte),
	}
}

func (b *benchmarkCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if data, exists := b.store[key]; exists {
		return bytes.NewReader(data), nil
	}
	return nil, cacher.ErrNotFound
}

func (b *benchmarkCacher) Put(ctx context.Context, cType string, key string, data io.Reader) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	bytes, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	b.store[key] = bytes
	return nil
}

func (b *benchmarkCacher) PutWithExpires(ctx context.Context, cType string, key string, data io.Reader, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	bytes, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	b.store[key] = bytes
	return nil
}

func (b *benchmarkCacher) Delete(ctx context.Context, cType string, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.store, key)
	return nil
}

func (b *benchmarkCacher) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for key := range b.store {
		if strings.HasPrefix(key, pattern) {
			delete(b.store, key)
		}
	}
	return nil
}

func (b *benchmarkCacher) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	return count, nil
}

func (b *benchmarkCacher) IncrementWithExpires(ctx context.Context, cType string, key string, count int64, ttl time.Duration) (int64, error) {
	return count, nil
}

func (b *benchmarkCacher) Close() error {
	return nil
}

func (b *benchmarkCacher) Driver() string {
	return "mock"
}

func (b *benchmarkCacher) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var keys []string
	for key := range b.store {
		// Simple pattern matching
		if pattern == "*" || pattern == key || strings.HasPrefix(key, pattern) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// WithPrefix methods
func (b *benchmarkCacher) GetWithPrefix(ctx context.Context, cType string, key string) (io.Reader, error) {
	return b.Get(ctx, cType, key)
}

func (b *benchmarkCacher) PutWithPrefix(ctx context.Context, cType string, key string, value io.Reader) error {
	return b.Put(ctx, cType, key, value)
}

func (b *benchmarkCacher) PutWithPrefixAndExpires(ctx context.Context, cType string, key string, value io.Reader, expires time.Duration) error {
	return b.PutWithExpires(ctx, cType, key, value, expires)
}

func (b *benchmarkCacher) DeleteWithPrefix(ctx context.Context, cType string, key string) error {
	return b.Delete(ctx, cType, key)
}

func (b *benchmarkCacher) DeleteWithPrefixByPattern(ctx context.Context, cType string, pattern string) error {
	return b.DeleteByPattern(ctx, cType, pattern)
}

func (b *benchmarkCacher) IncrementWithPrefix(ctx context.Context, cType string, key string, count int64) (int64, error) {
	return b.Increment(ctx, cType, key, count)
}

func (b *benchmarkCacher) IncrementWithPrefixAndExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	return b.IncrementWithExpires(ctx, cType, key, count, expires)
}

// benchmarkRoundTripper implements http.RoundTripper optimized for benchmarks
type benchmarkRoundTripper struct {
	response *http.Response
}

func newBenchmarkRoundTripper() *benchmarkRoundTripper {
	return &benchmarkRoundTripper{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Cache-Control": []string{"max-age=3600"},
				"ETag":          []string{`"benchmark-etag"`},
			},
			Body: io.NopCloser(strings.NewReader("benchmark response body")),
		},
	}
}

func (b *benchmarkRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the response to avoid issues with body reuse
	respClone := *b.response
	respClone.Body = io.NopCloser(strings.NewReader("benchmark response body"))
	return &respClone, nil
}

func BenchmarkHTTPCacheTransport_RoundTrip_CacheMiss(b *testing.B) {
	b.ReportAllocs()
	mockRT := newBenchmarkRoundTripper()
	mockCache := newBenchmarkCacher()
	transport := NewHTTPCacheTransport(mockRT, mockCache, DefaultCacheConfig())

	req := httptest.NewRequest("GET", "http://example.com/benchmark", nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := transport.RoundTrip(req)
			if err != nil {
				b.Fatalf("RoundTrip() error = %v", err)
			}
			// Consume the response body
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

func BenchmarkHTTPCacheTransport_RoundTrip_CacheHit(b *testing.B) {
	b.ReportAllocs()
	mockRT := newBenchmarkRoundTripper()
	mockCache := newBenchmarkCacher()
	transport := NewHTTPCacheTransport(mockRT, mockCache, DefaultCacheConfig())

	req := httptest.NewRequest("GET", "http://example.com/benchmark", nil)

	// Pre-populate cache
	resp, err := transport.RoundTrip(req)
	if err != nil {
		b.Fatalf("RoundTrip() error = %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := transport.RoundTrip(req)
			if err != nil {
				b.Fatalf("RoundTrip() error = %v", err)
			}
			// Consume the response body
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

func BenchmarkHTTPCacheTransport_RoundTrip_ConditionalRequest(b *testing.B) {
	b.ReportAllocs()
	mockRT := newBenchmarkRoundTripper()
	mockCache := newBenchmarkCacher()
	transport := NewHTTPCacheTransport(mockRT, mockCache, DefaultCacheConfig())

	req := httptest.NewRequest("GET", "http://example.com/benchmark", nil)
	req.Header.Set("If-None-Match", `"benchmark-etag"`)

	// Pre-populate cache
	resp, err := transport.RoundTrip(req)
	if err != nil {
		b.Fatalf("RoundTrip() error = %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := transport.RoundTrip(req)
			if err != nil {
				b.Fatalf("RoundTrip() error = %v", err)
			}
			// Consume the response body
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

func BenchmarkHTTPCacheTransport_ShouldBypassCache(b *testing.B) {
	b.ReportAllocs()
	transport := &HTTPCacheTransport{
		config: DefaultCacheConfig(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Cache-Control", "no-cache")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transport.shouldBypassCache(req)
	}
}

func BenchmarkHTTPCacheTransport_ShouldCacheResponse(b *testing.B) {
	b.ReportAllocs()
	transport := &HTTPCacheTransport{
		config: DefaultCacheConfig(),
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Cache-Control": []string{"max-age=3600"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transport.shouldCacheResponse(resp)
	}
}

func BenchmarkHTTPCacheTransport_CalculateTTL(b *testing.B) {
	b.ReportAllocs()
	transport := &HTTPCacheTransport{
		config: DefaultCacheConfig(),
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Cache-Control": []string{"max-age=3600"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transport.calculateTTL(resp)
	}
}

func BenchmarkHTTPCacheTransport_HandleConditionalRequest(b *testing.B) {
	b.ReportAllocs()
	transport := &HTTPCacheTransport{}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("If-None-Match", `"test-etag"`)

	cached := &HTTPCacheEntry{
		Header: make(http.Header),
		ETag:   `"test-etag"`,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transport.handleConditionalRequest(req, cached)
	}
}

func BenchmarkHTTPCacheTransport_IsCacheExpired(b *testing.B) {
	b.ReportAllocs()
	transport := &HTTPCacheTransport{
		config: DefaultCacheConfig(),
	}

	cached := &HTTPCacheEntry{
		Header: http.Header{
			"Cache-Control": []string{"max-age=3600"},
		},
		Timestamp: time.Now().Add(-time.Minute),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transport.isCacheExpired(cached)
	}
}

func BenchmarkHTTPCacheBody_Read(b *testing.B) {
	b.ReportAllocs()
	testData := strings.Repeat("test response body", 100) // ~1.7KB
	reader := strings.NewReader(testData)

	mockCache := newBenchmarkCacher()
	hasher := httpCacheXxhashPool.Get().(hash.Hash)
	hasher.Reset()

	body := &HTTPCacheBody{
		header:     make(http.Header),
		statusCode: http.StatusOK,
		buff:       new(bytes.Buffer),
		reader:     io.NopCloser(reader),
		key:        "benchmark-key",
		ttl:        time.Hour,
		store:      mockCache,
		hasher:     hasher,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset reader for each iteration
		body.reader = io.NopCloser(strings.NewReader(testData))
		body.buff.Reset()
		body.hasher.Reset()
		body.total = 0

		// Read all data
		io.Copy(io.Discard, body)
	}

	// Return hasher to pool
	httpCacheXxhashPool.Put(hasher)
}

func BenchmarkHTTPCacheBody_Close(b *testing.B) {
	b.ReportAllocs()
	testData := strings.Repeat("test response body", 100) // ~1.7KB

	mockCache := newBenchmarkCacher()
	hasher := httpCacheXxhashPool.Get().(hash.Hash)
	hasher.Reset()

	body := &HTTPCacheBody{
		header:     make(http.Header),
		statusCode: http.StatusOK,
		buff:       new(bytes.Buffer),
		reader:     io.NopCloser(strings.NewReader(testData)),
		key:        "benchmark-key",
		ttl:        time.Hour,
		store:      mockCache,
		hasher:     hasher,
	}

	// Pre-read the data
	io.Copy(io.Discard, body)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset for each iteration
		body.buff.Reset()
		body.hasher.Reset()
		body.total = len(testData)
		body.buff.WriteString(testData)
		body.hasher.Write([]byte(testData))

		body.Close()
	}

	// Return hasher to pool
	httpCacheXxhashPool.Put(hasher)
}

func BenchmarkCacheKeyGeneration(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/path?param1=value1&param2=value2", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "benchmark-agent")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This would be the actual cache key generation
		_ = fmt.Sprintf("%s|%s|%s|%s", req.Method, req.URL.String(), req.Header.Get("Accept"), req.Header.Get("User-Agent"))
	}
}

func BenchmarkETagGeneration(b *testing.B) {
	b.ReportAllocs()
	testData := strings.Repeat("test response body", 100) // ~1.7KB
	hasher := httpCacheXxhashPool.Get().(hash.Hash)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Reset()
		hasher.Write([]byte(testData))
		_ = fmt.Sprintf(`"%x"`, hasher.Sum(nil))
	}

	// Return hasher to pool
	httpCacheXxhashPool.Put(hasher)
}

// Memory allocation benchmarks
func BenchmarkHTTPCacheTransport_MemoryAllocations(b *testing.B) {
	b.ReportAllocs()
	mockRT := newBenchmarkRoundTripper()
	mockCache := newBenchmarkCacher()
	transport := NewHTTPCacheTransport(mockRT, mockCache, DefaultCacheConfig())

	req := httptest.NewRequest("GET", "http://example.com/benchmark", nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			b.Fatalf("RoundTrip() error = %v", err)
		}
		// Consume the response body
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func BenchmarkHTTPCacheBody_MemoryAllocations(b *testing.B) {
	b.ReportAllocs()
	testData := strings.Repeat("test response body", 100) // ~1.7KB

	mockCache := newBenchmarkCacher()
	hasher := httpCacheXxhashPool.Get().(hash.Hash)
	hasher.Reset()

	body := &HTTPCacheBody{
		header:     make(http.Header),
		statusCode: http.StatusOK,
		buff:       new(bytes.Buffer),
		reader:     io.NopCloser(strings.NewReader(testData)),
		key:        "benchmark-key",
		ttl:        time.Hour,
		store:      mockCache,
		hasher:     hasher,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset for each iteration
		body.buff.Reset()
		body.hasher.Reset()
		body.total = 0
		body.reader = io.NopCloser(strings.NewReader(testData))

		// Read all data
		io.Copy(io.Discard, body)
		body.Close()
	}

	// Return hasher to pool
	httpCacheXxhashPool.Put(hasher)
}

// Concurrent access benchmarks
func BenchmarkHTTPCacheTransport_ConcurrentAccess(b *testing.B) {
	b.ReportAllocs()
	mockRT := newBenchmarkRoundTripper()
	mockCache := newBenchmarkCacher()
	transport := NewHTTPCacheTransport(mockRT, mockCache, DefaultCacheConfig())

	req := httptest.NewRequest("GET", "http://example.com/benchmark", nil)

	// Pre-populate cache
	resp, err := transport.RoundTrip(req)
	if err != nil {
		b.Fatalf("RoundTrip() error = %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := transport.RoundTrip(req)
			if err != nil {
				b.Fatalf("RoundTrip() error = %v", err)
			}
			// Consume the response body
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

// Comparison benchmarks
func BenchmarkHTTPCacheTransport_vs_NoCache(b *testing.B) {
	b.ReportAllocs()
	// Benchmark with cache
	mockRT := newBenchmarkRoundTripper()
	mockCache := newBenchmarkCacher()
	cachedTransport := NewHTTPCacheTransport(mockRT, mockCache, DefaultCacheConfig())

	// Benchmark without cache (direct round tripper)
	noCacheTransport := newBenchmarkRoundTripper()

	req := httptest.NewRequest("GET", "http://example.com/benchmark", nil)

	// Pre-populate cache for cached transport
	resp, err := cachedTransport.RoundTrip(req)
	if err != nil {
		b.Fatalf("RoundTrip() error = %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	b.Run("WithCache", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp, err := cachedTransport.RoundTrip(req)
			if err != nil {
				b.Fatalf("RoundTrip() error = %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})

	b.Run("NoCache", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp, err := noCacheTransport.RoundTrip(req)
			if err != nil {
				b.Fatalf("RoundTrip() error = %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}
