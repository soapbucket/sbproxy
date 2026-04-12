package responsecache

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestChunkCacher_NoFlusher(t *testing.T) {
	store := NewMockKVStore()

	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create chunk cache config
	cfg := &config.ChunkCacheConfig{
		URLCache: config.URLCacheConfig{
			Enabled: true,
			TTL:     reqctx.Duration{Duration: 1 * time.Hour},
		},
	}

	chunkCacher, err := NewChunkCacher(store, cfg)
	if err != nil {
		t.Fatalf("Failed to create chunk cacher: %v", err)
	}

	// Create a response writer that doesn't implement http.Flusher
	w := &testResponseWriter{}

	// Set up request context with RequestData
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData := reqctx.NewRequestData()
	requestData.Config = map[string]any{
		reqctx.ConfigParamID: "test-config",
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	handler := chunkCacher.Middleware(next)
	handler.ServeHTTP(w, req)

	// Should call next handler because ResponseWriter doesn't implement Flusher
	if callCount != 1 {
		t.Errorf("Expected callCount to be 1, got %d", callCount)
	}
}

func TestChunkCacher_NoCache(t *testing.T) {
	store := NewMockKVStore()

	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create chunk cache config
	cfg := &config.ChunkCacheConfig{
		URLCache: config.URLCacheConfig{
			Enabled: true,
			TTL:     reqctx.Duration{Duration: 1 * time.Hour},
		},
		IgnoreNoCache: false,
	}

	chunkCacher, err := NewChunkCacher(store, cfg)
	if err != nil {
		t.Fatalf("Failed to create chunk cacher: %v", err)
	}

	// Request with no-cache header
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Cache-Control", "no-cache")
	
	// Set up request context with RequestData
	requestData := reqctx.NewRequestData()
	requestData.Config = map[string]any{
		reqctx.ConfigParamID: "test-config",
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	w := httptest.NewRecorder()
	handler := chunkCacher.Middleware(next)
	handler.ServeHTTP(w, req)

	// Should call next handler
	if callCount != 1 {
		t.Errorf("Expected callCount to be 1, got %d", callCount)
	}
}

func TestChunkCacher_IgnoreNoCache(t *testing.T) {
	store := NewMockKVStore()

	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create chunk cache config with ignoreNoCache = true
	cfg := &config.ChunkCacheConfig{
		URLCache: config.URLCacheConfig{
			Enabled: true,
			TTL:     reqctx.Duration{Duration: 1 * time.Hour},
		},
		IgnoreNoCache: true,
	}

	chunkCacher, err := NewChunkCacher(store, cfg)
	if err != nil {
		t.Fatalf("Failed to create chunk cacher: %v", err)
	}

	// First request
	req1 := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData1 := reqctx.NewRequestData()
	requestData1.Config = map[string]any{
		reqctx.ConfigParamID: "test-config",
	}
	req1 = req1.WithContext(reqctx.SetRequestData(req1.Context(), requestData1))
	w1 := httptest.NewRecorder()
	handler := chunkCacher.Middleware(next)
	handler.ServeHTTP(w1, req1)

	// Wait a bit for the cache to be saved
	time.Sleep(50 * time.Millisecond)

	// Second request with no-cache header
	req2 := httptest.NewRequest("GET", "http://example.com/test", nil)
	req2.Header.Set("Cache-Control", "no-cache")
	requestData2 := reqctx.NewRequestData()
	requestData2.Config = map[string]any{
		reqctx.ConfigParamID: "test-config",
	}
	req2 = req2.WithContext(reqctx.SetRequestData(req2.Context(), requestData2))
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	// Should still use cache because ignoreNoCache is true
	if callCount != 1 {
		t.Errorf("Expected callCount to be 1 (cached), got %d", callCount)
	}
}

func TestChunkCacher_WithFlusher(t *testing.T) {
	store := NewMockKVStore()

	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create chunk cache config
	cfg := &config.ChunkCacheConfig{
		URLCache: config.URLCacheConfig{
			Enabled: true,
			TTL:     reqctx.Duration{Duration: 1 * time.Hour},
		},
	}

	chunkCacher, err := NewChunkCacher(store, cfg)
	if err != nil {
		t.Fatalf("Failed to create chunk cacher: %v", err)
	}

	// First request
	req1 := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData1 := reqctx.NewRequestData()
	requestData1.Config = map[string]any{
		reqctx.ConfigParamID: "test-config",
	}
	req1 = req1.WithContext(reqctx.SetRequestData(req1.Context(), requestData1))
	w1 := httptest.NewRecorder()
	handler := chunkCacher.Middleware(next)
	handler.ServeHTTP(w1, req1)

	// Wait a bit for the cache to be saved
	time.Sleep(50 * time.Millisecond)

	// Second request - should use cache
	req2 := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData2 := reqctx.NewRequestData()
	requestData2.Config = map[string]any{
		reqctx.ConfigParamID: "test-config",
	}
	req2 = req2.WithContext(reqctx.SetRequestData(req2.Context(), requestData2))
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	// Should still be 1 because second request should be served from cache
	if callCount != 1 {
		t.Errorf("Expected callCount to be 1 (cached), got %d", callCount)
	}
}

// testResponseWriter is a simple response writer for testing
type testResponseWriter struct {
	header http.Header
	status int
	body   []byte
}

func (w *testResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *testResponseWriter) Write(data []byte) (int, error) {
	w.body = append(w.body, data...)
	return len(data), nil
}

func (w *testResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}
