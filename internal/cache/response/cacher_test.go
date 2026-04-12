package responsecache

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCacher(t *testing.T) {
	store := NewMockKVStore()

	// Create a test handler that returns different content each time
	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create cacher middleware
	cacherMiddleware := Cacher(store, false, false, 0, next)

	// First request - should call next handler
	req1 := httptest.NewRequest("GET", "http://example.com/test", nil)
	w1 := httptest.NewRecorder()
	cacherMiddleware.ServeHTTP(w1, req1)

	if callCount != 1 {
		t.Errorf("Expected callCount to be 1, got %d", callCount)
	}
	if w1.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w1.Code)
	}

	// Wait a bit for the cache to be saved
	time.Sleep(200 * time.Millisecond)

	// Second request - should use cache
	req2 := httptest.NewRequest("GET", "http://example.com/test", nil)
	w2 := httptest.NewRecorder()
	cacherMiddleware.ServeHTTP(w2, req2)

	// Should still be 1 because second request should be served from cache
	if callCount != 1 {
		t.Errorf("Expected callCount to still be 1 (cached), got %d", callCount)
	}
	if w2.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w2.Code)
	}
}

func TestCacher_NoCache(t *testing.T) {
	store := NewMockKVStore()

	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	cacherMiddleware := Cacher(store, false, false, 0, next)

	// Request with no-cache header
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Cache-Control", "no-cache")
	w := httptest.NewRecorder()
	cacherMiddleware.ServeHTTP(w, req)

	// Should call next handler even if cache exists
	if callCount != 1 {
		t.Errorf("Expected callCount to be 1, got %d", callCount)
	}
}

func TestCacher_IgnoreNoCache(t *testing.T) {
	store := NewMockKVStore()

	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Create cacher with ignoreNoCache = true
	cacherMiddleware := Cacher(store, true, false, 0, next)

	// First request
	req1 := httptest.NewRequest("GET", "http://example.com/test", nil)
	w1 := httptest.NewRecorder()
	cacherMiddleware.ServeHTTP(w1, req1)

	// Wait a bit for the cache to be saved
	time.Sleep(200 * time.Millisecond)

	// Second request with no-cache header
	req2 := httptest.NewRequest("GET", "http://example.com/test", nil)
	req2.Header.Set("Cache-Control", "no-cache")
	w2 := httptest.NewRecorder()
	cacherMiddleware.ServeHTTP(w2, req2)

	// Should still use cache because ignoreNoCache is true
	if callCount != 1 {
		t.Errorf("Expected callCount to be 1 (cached), got %d", callCount)
	}
}

func TestCacher_ETag(t *testing.T) {
	store := NewMockKVStore()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "\"test-etag\"")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	cacherMiddleware := Cacher(store, false, false, 0, next)

	// First request
	req1 := httptest.NewRequest("GET", "http://example.com/test", nil)
	w1 := httptest.NewRecorder()
	cacherMiddleware.ServeHTTP(w1, req1)

	// Wait a bit for the cache to be saved
	time.Sleep(200 * time.Millisecond)

	// Second request with matching ETag
	req2 := httptest.NewRequest("GET", "http://example.com/test", nil)
	req2.Header.Set("If-None-Match", "\"test-etag\"")
	w2 := httptest.NewRecorder()
	cacherMiddleware.ServeHTTP(w2, req2)

	// Should return 304 Not Modified
	if w2.Code != http.StatusNotModified {
		t.Errorf("Expected status %d, got %d", http.StatusNotModified, w2.Code)
	}
}

func TestCacher_LastModified(t *testing.T) {
	store := NewMockKVStore()

	lastModified := time.Now().Format(time.RFC1123)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	cacherMiddleware := Cacher(store, false, false, 0, next)

	// First request
	req1 := httptest.NewRequest("GET", "http://example.com/lastmodified-unique", nil)
	w1 := httptest.NewRecorder()
	cacherMiddleware.ServeHTTP(w1, req1)

	// Wait a bit for the cache to be saved
	time.Sleep(200 * time.Millisecond)

	// Second request with If-Modified-Since header
	req2 := httptest.NewRequest("GET", "http://example.com/lastmodified-unique", nil)
	req2.Header.Set("If-Modified-Since", time.Now().Add(time.Hour).Format(time.RFC1123))
	w2 := httptest.NewRecorder()
	cacherMiddleware.ServeHTTP(w2, req2)

	// Should return 304 Not Modified
	if w2.Code != http.StatusNotModified {
		t.Errorf("Expected status %d, got %d", http.StatusNotModified, w2.Code)
	}
}
