package callback

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestCallback_Fetch(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter)
		callback       *Callback
		expectedBody   string
		expectedCT     string
		expectError    bool
	}{
		{
			name: "fetch HTML content",
			serverResponse: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte("<h1>Error Page</h1>"))
			},
			callback: &Callback{
				URL:           "",
				CacheDuration: reqctx.Duration{}, // No caching for this test
			},
			expectedBody: "<h1>Error Page</h1>",
			expectedCT:   "text/html",
			expectError:  false,
		},
		{
			name: "fetch binary content",
			serverResponse: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "image/png")
				w.Write([]byte("fake-png-data"))
			},
			callback: &Callback{
				URL:           "",
				CacheDuration: reqctx.Duration{},
			},
			expectedBody: "fake-png-data",
			expectedCT:   "image/png",
			expectError:  false,
		},
		{
			name: "fetch with custom headers",
			serverResponse: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("X-Custom-Header", "custom-value")
				w.Write([]byte("Content"))
			},
			callback: &Callback{
				URL:           "",
				CacheDuration: reqctx.Duration{},
			},
			expectedBody: "Content",
			expectedCT:   "text/html",
			expectError:  false,
		},
		{
			name: "fetch with non-200 status",
			serverResponse: func(w http.ResponseWriter) {
				w.WriteHeader(404)
				w.Write([]byte("Not Found"))
			},
			callback: &Callback{
				URL:           "",
				CacheDuration: reqctx.Duration{},
			},
			expectedBody: "Not Found",
			expectedCT:   "application/octet-stream", // Default when no Content-Type
			expectError:  false,                      // Fetch allows non-200
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.serverResponse(w)
			}))
			defer server.Close()

			tt.callback.URL = server.URL
			// Initialize callback by setting cache key (normally done in UnmarshalJSON)
			tt.callback.cacheKey = "test-cache-key"

			ctx := context.Background()
			fetchResp, err := tt.callback.Fetch(ctx, map[string]any{"test": "data"})

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if fetchResp == nil {
				t.Fatal("expected FetchResponse but got nil")
			}

			if string(fetchResp.Body) != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, string(fetchResp.Body))
			}

			if fetchResp.ContentType != tt.expectedCT {
				t.Errorf("expected Content-Type %q, got %q", tt.expectedCT, fetchResp.ContentType)
			}
		})
	}
}

func TestCallback_Fetch_WithCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<h1>Cached Content</h1>"))
	}))
	defer server.Close()

	callback := &Callback{
		URL:           server.URL,
		CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
	}

	// Initialize callback by setting cache key
	callback.cacheKey = "test-cache-key"

	// Create a cache
	memCache, err := cacher.NewCacher(cacher.Settings{
		Driver:     "memory",
		MaxObjects: 1000,
		MaxMemory:  10 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer memCache.Close()

	cache := NewCallbackCache(memCache)
	ctx := WithCache(context.Background(), cache)

	// First fetch - should hit server
	fetchResp1, err := callback.Fetch(ctx, map[string]any{"key": "value"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 server call, got %d", callCount)
	}

	if string(fetchResp1.Body) != "<h1>Cached Content</h1>" {
		t.Errorf("unexpected body: %q", string(fetchResp1.Body))
	}

	// Second fetch with same data - should hit cache
	fetchResp2, err := callback.Fetch(ctx, map[string]any{"key": "value"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 server call (cached), got %d", callCount)
	}

	if string(fetchResp2.Body) != "<h1>Cached Content</h1>" {
		t.Errorf("unexpected cached body: %q", string(fetchResp2.Body))
	}
}

func TestCallback_Fetch_Base64Content(t *testing.T) {
	originalContent := []byte("<h1>Binary Content</h1>")
	encodedContent := base64.StdEncoding.EncodeToString(originalContent)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(encodedContent))
	}))
	defer server.Close()

	callback := &Callback{
		URL:           server.URL,
		CacheDuration: reqctx.Duration{},
	}

	// Initialize callback by setting cache key
	callback.cacheKey = "test-cache-key"

	ctx := context.Background()
	fetchResp, err := callback.Fetch(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Fetch returns the raw response (base64-encoded in this case)
	// Decoding should be done by the caller
	if string(fetchResp.Body) != encodedContent {
		t.Errorf("expected base64-encoded content, got %q", string(fetchResp.Body))
	}
}

func TestCallbackCache_GetFetch_PutFetch(t *testing.T) {
	memCache, err := cacher.NewCacher(cacher.Settings{
		Driver:     "memory",
		MaxObjects: 1000,
		MaxMemory:  10 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer memCache.Close()

	cache := NewCallbackCache(memCache)
	ctx := context.Background()

	fetchResp := &FetchResponse{
		Body:        []byte("<h1>Test</h1>"),
		Headers:     make(http.Header),
		StatusCode:  200,
		ContentType: "text/html",
	}
	fetchResp.Headers.Set("Content-Type", "text/html")
	fetchResp.Headers.Set("X-Custom", "value")

	cacheKey := "test-fetch-key"
	ttl := 1 * time.Hour

	// Put fetch response
	err = cache.PutFetch(ctx, cacheKey, fetchResp, ttl)
	if err != nil {
		t.Fatalf("failed to put fetch response: %v", err)
	}

	// Get fetch response
	cachedResp, found, err := cache.GetFetch(ctx, cacheKey)
	if err != nil {
		t.Fatalf("failed to get fetch response: %v", err)
	}

	if !found {
		t.Error("expected cached response to be found")
	}

	if cachedResp == nil {
		t.Fatal("expected cached response but got nil")
	}

	if string(cachedResp.Body) != string(fetchResp.Body) {
		t.Errorf("expected body %q, got %q", string(fetchResp.Body), string(cachedResp.Body))
	}

	if cachedResp.StatusCode != fetchResp.StatusCode {
		t.Errorf("expected status code %d, got %d", fetchResp.StatusCode, cachedResp.StatusCode)
	}

	if cachedResp.ContentType != fetchResp.ContentType {
		t.Errorf("expected content type %q, got %q", fetchResp.ContentType, cachedResp.ContentType)
	}

	if cachedResp.Headers.Get("X-Custom") != "value" {
		t.Errorf("expected header X-Custom=value, got %q", cachedResp.Headers.Get("X-Custom"))
	}
}
