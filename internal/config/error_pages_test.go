package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/config/callback"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/internal/cache/store"
)

// mockCacher is a simple in-memory cache for testing
type mockCacher struct {
	data map[string][]byte
}

func newMockCacher() *mockCacher {
	return &mockCacher{
		data: make(map[string][]byte),
	}
}

func (m *mockCacher) Get(ctx context.Context, cacheType, key string) (io.Reader, error) {
	fullKey := cacheType + ":" + key
	if data, ok := m.data[fullKey]; ok {
		return bytes.NewReader(data), nil
	}
	return nil, cacher.ErrNotFound
}

func (m *mockCacher) Put(ctx context.Context, cacheType, key string, reader io.Reader) error {
	fullKey := cacheType + ":" + key
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	m.data[fullKey] = data
	return nil
}

func (m *mockCacher) PutWithExpires(ctx context.Context, cacheType, key string, reader io.Reader, expires time.Duration) error {
	// For testing, we'll just store it without expiration tracking
	return m.Put(ctx, cacheType, key, reader)
}

func (m *mockCacher) Delete(ctx context.Context, cacheType, key string) error {
	fullKey := cacheType + ":" + key
	delete(m.data, fullKey)
	return nil
}

func (m *mockCacher) DeleteByPattern(ctx context.Context, cacheType, pattern string) error {
	// Not needed for tests
	return nil
}

func (m *mockCacher) Increment(ctx context.Context, cacheType, key string, delta int64) (int64, error) {
	return 0, nil
}

func (m *mockCacher) IncrementWithExpires(ctx context.Context, cacheType, key string, delta int64, expires time.Duration) (int64, error) {
	return 0, nil
}

func (m *mockCacher) Driver() string {
	return "mock"
}

func (m *mockCacher) Close() error {
	return nil
}

func (m *mockCacher) ListKeys(ctx context.Context, cacheType, pattern string) ([]string, error) {
	var keys []string
	for fullKey := range m.data {
		if strings.HasPrefix(fullKey, cacheType+":") {
			key := strings.TrimPrefix(fullKey, cacheType+":")
			if pattern == "*" || pattern == key || strings.HasPrefix(key, pattern) {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
}

func TestServeStaticErrorPage(t *testing.T) {
	tests := []struct {
		name           string
		errorPage      *ErrorPage
		statusCode     int
		expectedBody   string
		expectedStatus int
		expectError    bool
	}{
		{
			name: "simple HTML body",
			errorPage: &ErrorPage{
				Body:        "<html><body><h1>404 Not Found</h1></body></html>",
				ContentType: "text/html",
			},
			statusCode:     404,
			expectedBody:   "<html><body><h1>404 Not Found</h1></body></html>",
			expectedStatus: 404,
			expectError:    false,
		},
		{
			name: "base64 encoded body",
			errorPage: &ErrorPage{
				BodyBase64:  base64.StdEncoding.EncodeToString([]byte("<h1>Error</h1>")),
				ContentType: "text/html",
			},
			statusCode:     500,
			expectedBody:   "<h1>Error</h1>",
			expectedStatus: 500,
			expectError:    false,
		},
		{
			name: "JSON body",
			errorPage: &ErrorPage{
				JSONBody:    json.RawMessage(`{"error": "Not Found"}`),
				ContentType: "application/json",
			},
			statusCode:     404,
			expectedBody:   `{"error":"Not Found"}`,
			expectedStatus: 404,
			expectError:    false,
		},
		{
			name: "custom status code override",
			errorPage: &ErrorPage{
				Body:        "Custom 404",
				StatusCode:  200, // Override to 200
				ContentType: "text/html",
			},
			statusCode:     404,
			expectedBody:   "Custom 404",
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name: "no body - uses default",
			errorPage: &ErrorPage{
				ContentType: "text/html",
			},
			statusCode:     404,
			expectedBody:   "Not Found",
			expectedStatus: 404,
			expectError:    false,
		},
		{
			name: "invalid base64",
			errorPage: &ErrorPage{
				BodyBase64:  "invalid-base64!!!",
				ContentType: "text/html",
			},
			statusCode:  500,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ID:       "test-origin",
				Hostname: "test.example.com",
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/test", nil)

			result := cfg.serveStaticErrorPage(w, r, tt.statusCode, nil, tt.errorPage)

			if tt.expectError {
				if result {
					t.Error("expected error but got success")
				}
				return
			}

			if !result {
				t.Error("expected success but got error")
				return
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			body := w.Body.String()
			if body != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, body)
			}
		})
	}
}

func TestServeStaticErrorPage_WithCache(t *testing.T) {
	cfg := &Config{
		ID:       "test-origin",
		Hostname: "test.example.com",
		l3Cache:  newMockCacher(),
	}

	errorPage := &ErrorPage{
		Body:        "<h1>Cached Error</h1>",
		ContentType: "text/html",
	}

	// First request - should cache
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/test", nil)
	r1 = r1.WithContext(context.Background())

	result1 := cfg.serveStaticErrorPage(w1, r1, 404, nil, errorPage)
	if !result1 {
		t.Fatal("expected first request to succeed")
	}

	if w1.Body.String() != "<h1>Cached Error</h1>" {
		t.Errorf("unexpected body: %q", w1.Body.String())
	}

	// Second request - should serve from cache
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/test", nil)
	r2 = r2.WithContext(context.Background())

	result2 := cfg.serveStaticErrorPage(w2, r2, 404, nil, errorPage)
	if !result2 {
		t.Fatal("expected second request to succeed")
	}

	if w2.Body.String() != "<h1>Cached Error</h1>" {
		t.Errorf("unexpected cached body: %q", w2.Body.String())
	}
}

func TestServeStaticErrorPage_Template(t *testing.T) {
	cfg := &Config{
		ID:       "test-origin",
		Hostname: "test.example.com",
	}

	errorPage := &ErrorPage{
		Body:        "Status: {{ status_code }}, Error: {{ error }}",
		Template:    true,
		ContentType: "text/html",
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r = r.WithContext(context.Background())

	result := cfg.serveStaticErrorPage(w, r, 404, nil, errorPage)
	if !result {
		t.Fatal("expected template rendering to succeed")
	}

	body := w.Body.String()
	if body == "Status: {{ status_code }}, Error: {{ error }}" {
		t.Error("template was not rendered")
	}
	if !errorPageTestContains(body, "404") {
		t.Errorf("expected rendered template to contain status code, got %q", body)
	}
}

func TestServeStaticErrorPage_TemplateError(t *testing.T) {
	cfg := &Config{
		ID:       "test-origin",
		Hostname: "test.example.com",
	}

	errorPage := &ErrorPage{
		Body:        "{{ invalid template syntax }",
		Template:    true,
		ContentType: "text/html",
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r = r.WithContext(context.Background())

	result := cfg.serveStaticErrorPage(w, r, 404, nil, errorPage)
	if result {
		t.Error("expected template error to return false")
	}
}

func TestServeErrorPageFromCallback(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter)
		errorPage      *ErrorPage
		statusCode     int
		expectedBody   string
		expectedStatus int
		expectError    bool
	}{
		{
			name: "successful callback fetch",
			serverResponse: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte("<h1>Callback Error</h1>"))
			},
			errorPage: &ErrorPage{
				Callback: &callback.Callback{
					URL:           "",
					CacheDuration: reqctx.Duration{},
				},
				ContentType: "text/html",
			},
			statusCode:     404,
			expectedBody:   "<h1>Callback Error</h1>",
			expectedStatus: 404,
			expectError:    false,
		},
		{
			name: "callback with base64 decode",
			serverResponse: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/octet-stream")
				encoded := base64.StdEncoding.EncodeToString([]byte("<h1>Decoded</h1>"))
				w.Write([]byte(encoded))
			},
			errorPage: &ErrorPage{
				Callback: &callback.Callback{
					URL:           "",
					CacheDuration: reqctx.Duration{},
				},
				DecodeBase64: true,
				ContentType:  "text/html",
			},
			statusCode:     500,
			expectedBody:   "<h1>Decoded</h1>",
			expectedStatus: 500,
			expectError:    false,
		},
		{
			name: "callback with custom status code",
			serverResponse: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte("Custom Error"))
			},
			errorPage: &ErrorPage{
				Callback: &callback.Callback{
					URL:           "",
					CacheDuration: reqctx.Duration{},
				},
				StatusCode:  200,
				ContentType: "text/html",
			},
			statusCode:     404,
			expectedBody:   "Custom Error",
			expectedStatus: 200,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.serverResponse(w)
			}))
			defer server.Close()

			tt.errorPage.Callback.URL = server.URL
			// Initialize callback by setting cache key (normally done in UnmarshalJSON)
			// We'll use a workaround by calling GetCacheKey which initializes it
			_ = tt.errorPage.Callback.GetCacheKey()

			cfg := &Config{
				ID:       "test-origin",
				Hostname: "test.example.com",
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/test", nil)
			r = r.WithContext(context.Background())

			result := cfg.serveErrorPageFromCallback(w, r, tt.statusCode, nil, tt.errorPage)

			if tt.expectError {
				if result {
					t.Error("expected error but got success")
				}
				return
			}

			if !result {
				t.Error("expected success but got error")
				return
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			body := w.Body.String()
			if body != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, body)
			}
		})
	}
}

func TestServeErrorPageFromCallback_WithCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<h1>Cached Callback Error</h1>"))
	}))
	defer server.Close()

	cfg := &Config{
		ID:       "test-origin",
		Hostname: "test.example.com",
		l3Cache:  newMockCacher(),
	}

	errorPage := &ErrorPage{
		Callback: &callback.Callback{
			URL:           server.URL,
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		},
		ContentType: "text/html",
	}
	// Initialize callback cache key
	_ = errorPage.Callback.GetCacheKey()

	// First request - should fetch from callback
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/test", nil)
	r1 = r1.WithContext(context.Background())

	result1 := cfg.serveErrorPageFromCallback(w1, r1, 404, nil, errorPage)
	if !result1 {
		t.Fatal("expected first request to succeed")
	}

	if callCount != 1 {
		t.Errorf("expected 1 callback call, got %d", callCount)
	}

	if w1.Body.String() != "<h1>Cached Callback Error</h1>" {
		t.Errorf("unexpected body: %q", w1.Body.String())
	}

	// Second request - should serve from cache
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/test", nil)
	r2 = r2.WithContext(context.Background())

	result2 := cfg.serveErrorPageFromCallback(w2, r2, 404, nil, errorPage)
	if !result2 {
		t.Fatal("expected second request to succeed")
	}

	// Should still be 1 call (served from cache)
	if callCount != 1 {
		t.Errorf("expected still 1 callback call (cached), got %d", callCount)
	}

	if w2.Body.String() != "<h1>Cached Callback Error</h1>" {
		t.Errorf("unexpected cached body: %q", w2.Body.String())
	}
}

func TestServeErrorPageFromCallback_Template(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("Status: {{ status_code }}, Origin: {{ origin_id }}"))
	}))
	defer server.Close()

	cfg := &Config{
		ID:       "test-origin",
		Hostname: "test.example.com",
	}

	errorPage := &ErrorPage{
		Callback: &callback.Callback{
			URL:           server.URL,
			CacheDuration: reqctx.Duration{},
		},
		Template:    true,
		ContentType: "text/html",
	}
	// Initialize callback cache key
	_ = errorPage.Callback.GetCacheKey()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r = r.WithContext(context.Background())

	result := cfg.serveErrorPageFromCallback(w, r, 404, nil, errorPage)
	if !result {
		t.Fatal("expected template rendering to succeed")
	}

	body := w.Body.String()
	if body == "Status: {{ status_code }}, Origin: {{ origin_id }}" {
		t.Error("template was not rendered")
	}
	if !errorPageTestContains(body, "404") {
		t.Errorf("expected rendered template to contain status code, got %q", body)
	}
	if !errorPageTestContains(body, "test-origin") {
		t.Errorf("expected rendered template to contain origin ID, got %q", body)
	}
}

func TestServeErrorPageFromCallback_TemplateError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("{{ invalid template syntax }"))
	}))
	defer server.Close()

	cfg := &Config{
		ID:       "test-origin",
		Hostname: "test.example.com",
	}

	errorPage := &ErrorPage{
		Callback: &callback.Callback{
			URL:           server.URL,
			CacheDuration: reqctx.Duration{},
		},
		Template:    true,
		ContentType: "text/html",
	}
	// Initialize callback cache key
	_ = errorPage.Callback.GetCacheKey()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r = r.WithContext(context.Background())

	result := cfg.serveErrorPageFromCallback(w, r, 404, nil, errorPage)
	if result {
		t.Error("expected template error to return false")
	}
}

func TestServeErrorPageFromCallback_CacheReadError(t *testing.T) {
	// Create a cache that returns an error on Get
	failingCache := &failingCache{shouldFailGet: true}

	cfg := &Config{
		ID:       "test-origin",
		Hostname: "test.example.com",
		l3Cache:  failingCache,
	}

	errorPage := &ErrorPage{
		Callback: &callback.Callback{
			URL:           "http://example.com",
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		},
		ContentType: "text/html",
	}
	// Initialize callback cache key
	_ = errorPage.Callback.GetCacheKey()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r = r.WithContext(context.Background())

	// Should return false when cache read fails
	result := cfg.serveErrorPageFromCallback(w, r, 404, nil, errorPage)
	if result {
		t.Error("expected cache read error to return false")
	}
}

func TestFindErrorPage(t *testing.T) {
	tests := []struct {
		name       string
		errorPages ErrorPages
		statusCode int
		expected   bool
	}{
		{
			name: "exact status code match",
			errorPages: ErrorPages{
				{Status: []int{404}, Body: "404 Error"},
				{Status: []int{500}, Body: "500 Error"},
			},
			statusCode: 404,
			expected:   true,
		},
		{
			name: "catch-all page",
			errorPages: ErrorPages{
				{Status: []int{404}, Body: "404 Error"},
				{Body: "Generic Error"}, // No status codes = catch-all
			},
			statusCode: 500,
			expected:   true,
		},
		{
			name: "no match",
			errorPages: ErrorPages{
				{Status: []int{404}, Body: "404 Error"},
			},
			statusCode: 500,
			expected:   false,
		},
		{
			name: "priority - specific over catch-all",
			errorPages: ErrorPages{
				{Body: "Generic Error"},                 // Catch-all
				{Status: []int{404}, Body: "404 Error"}, // Specific
			},
			statusCode: 404,
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, found := tt.errorPages.FindErrorPage(tt.statusCode)
			if found != tt.expected {
				t.Errorf("expected found=%v, got %v", tt.expected, found)
			}
			if found && page == nil {
				t.Error("found page but got nil")
			}
		})
	}
}

// failingCache is a cache that can be configured to fail operations
type failingCache struct {
	shouldFailGet        bool
	shouldFailPut        bool
	shouldFailPutExpires bool
}

func (f *failingCache) Get(ctx context.Context, cacheType, key string) (io.Reader, error) {
	if f.shouldFailGet {
		// Return a reader that will fail on Read to simulate cache read error
		return &failingReader{}, nil
	}
	return nil, cacher.ErrNotFound
}

func (f *failingCache) Put(ctx context.Context, cacheType, key string, reader io.Reader) error {
	if f.shouldFailPut {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (f *failingCache) PutWithExpires(ctx context.Context, cacheType, key string, reader io.Reader, expires time.Duration) error {
	if f.shouldFailPutExpires {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (f *failingCache) Delete(ctx context.Context, cacheType, key string) error {
	return nil
}

func (f *failingCache) DeleteByPattern(ctx context.Context, cacheType, pattern string) error {
	return nil
}

func (f *failingCache) Increment(ctx context.Context, cacheType, key string, delta int64) (int64, error) {
	return 0, nil
}

func (f *failingCache) IncrementWithExpires(ctx context.Context, cacheType, key string, delta int64, expires time.Duration) (int64, error) {
	return 0, nil
}

func (f *failingCache) Driver() string {
	return "failing"
}

func (f *failingCache) Close() error {
	return nil
}

func (f *failingCache) ListKeys(ctx context.Context, cacheType, pattern string) ([]string, error) {
	return nil, nil
}

// failingReader is a reader that always fails
type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

// Helper function to check if string contains substring
func errorPageTestContains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestErrorPages_DefaultContentType tests that DefaultContentType is used as fallback for error pages
func TestErrorPages_DefaultContentType(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *Config
		errorPage  *ErrorPage
		expectedCT string
	}{
		{
			name: "default_content_type used when error page has no content_type",
			cfg: &Config{
				ID:                 "test-origin",
				Hostname:           "test.example.com",
				DefaultContentType: "application/json",
			},
			errorPage: &ErrorPage{
				Body: `{"error": "not found"}`,
			},
			expectedCT: "application/json",
		},
		{
			name: "fallback to text/html when no default_content_type and no error page content_type",
			cfg: &Config{
				ID:       "test-origin",
				Hostname: "test.example.com",
			},
			errorPage: &ErrorPage{
				Body: "<h1>Not Found</h1>",
			},
			expectedCT: "text/html",
		},
		{
			name: "explicit error page content_type overrides default_content_type",
			cfg: &Config{
				ID:                 "test-origin",
				Hostname:           "test.example.com",
				DefaultContentType: "application/json",
			},
			errorPage: &ErrorPage{
				Body:        "<error>not found</error>",
				ContentType: "text/xml",
			},
			expectedCT: "text/xml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/test", nil)

			result := tt.cfg.serveStaticErrorPage(w, r, 404, nil, tt.errorPage)
			if !result {
				t.Fatal("expected error page to be served")
			}

			ct := w.Header().Get("Content-Type")
			if ct != tt.expectedCT {
				t.Errorf("expected Content-Type %q, got %q", tt.expectedCT, ct)
			}
		})
	}
}

// TestRetryHandler tests the retry handler functionality with error pages
func TestRetryHandler(t *testing.T) {
	tests := []struct {
		name                 string
		maxRetries           int
		retryableStatusCodes []int
		serverResponses      []int // Sequence of status codes server returns
		expectedAttempts     int
		expectedFinalStatus  int
		expectError          bool
	}{
		{
			name:                 "success on first attempt",
			maxRetries:           3,
			retryableStatusCodes: []int{502, 503, 504, 429},
			serverResponses:      []int{200},
			expectedAttempts:     1,
			expectedFinalStatus:  200,
			expectError:          false,
		},
		{
			name:                 "retry on 503 then succeed",
			maxRetries:           3,
			retryableStatusCodes: []int{502, 503, 504, 429},
			serverResponses:      []int{503, 503, 200},
			expectedAttempts:     3,
			expectedFinalStatus:  200,
			expectError:          false,
		},
		{
			name:                 "exhaust retries on 502",
			maxRetries:           2,
			retryableStatusCodes: []int{502, 503, 504, 429},
			serverResponses:      []int{502, 502, 502},
			expectedAttempts:     3, // 1 initial + 2 retries
			expectedFinalStatus:  502,
			expectError:          false,
		},
		{
			name:                 "no retry on 404",
			maxRetries:           3,
			retryableStatusCodes: []int{502, 503, 504, 429},
			serverResponses:      []int{404},
			expectedAttempts:     1,
			expectedFinalStatus:  404,
			expectError:          false,
		},
		{
			name:                 "retry on 429 rate limit",
			maxRetries:           3,
			retryableStatusCodes: []int{502, 503, 504, 429},
			serverResponses:      []int{429, 429, 200},
			expectedAttempts:     3,
			expectedFinalStatus:  200,
			expectError:          false,
		},
		{
			name:                 "custom retryable status codes",
			maxRetries:           2,
			retryableStatusCodes: []int{500, 501},
			serverResponses:      []int{500, 501, 200},
			expectedAttempts:     3,
			expectedFinalStatus:  200,
			expectError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				if attempts <= len(tt.serverResponses) {
					status := tt.serverResponses[attempts-1]
					w.WriteHeader(status)
					w.Write([]byte(http.StatusText(status)))
				} else {
					// If we've exhausted responses, return last one
					w.WriteHeader(tt.serverResponses[len(tt.serverResponses)-1])
				}
			}))
			defer server.Close()

			// Create retry transport
			baseTransport := &http.Transport{}
			defer baseTransport.CloseIdleConnections()

			retryTransport := &transport.RetryTransport{
				Base:                 baseTransport,
				MaxRetries:           tt.maxRetries,
				InitialDelay:         10 * time.Millisecond, // Fast for testing
				RetryableStatusCodes: tt.retryableStatusCodes,
			}

			client := &http.Client{
				Transport: retryTransport,
				Timeout:   5 * time.Second,
			}

			req, _ := http.NewRequest("GET", server.URL, nil)
			resp, err := client.Do(req)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedFinalStatus {
				t.Errorf("expected final status %d, got %d", tt.expectedFinalStatus, resp.StatusCode)
			}

			if attempts != tt.expectedAttempts {
				t.Errorf("expected %d attempts, got %d", tt.expectedAttempts, attempts)
			}
		})
	}
}

// TestRetryHandlerWithErrorPages tests retry handler with error page serving
func TestRetryHandlerWithErrorPages(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		// Always return 503 (retryable)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service Unavailable"))
	}))
	defer server.Close()

	// Create retry transport
	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	retryTransport := &transport.RetryTransport{
		Base:                 baseTransport,
		MaxRetries:           2,
		InitialDelay:         10 * time.Millisecond,
		RetryableStatusCodes: []int{502, 503, 504, 429},
	}

	client := &http.Client{
		Transport: retryTransport,
		Timeout:   5 * time.Second,
	}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// Should have exhausted retries and returned 503
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", resp.StatusCode)
	}

	// Should have made 3 attempts (1 initial + 2 retries)
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// TestMaxRequestsHandler tests the max requests/connection limiter handler
func TestMaxRequestsHandler(t *testing.T) {
	tests := []struct {
		name               string
		maxConnections     int
		concurrentRequests int
		expectedSuccess    int
		expected503        int
		serverDelay        time.Duration
	}{
		{
			name:               "limit to 2 connections",
			maxConnections:     2,
			concurrentRequests: 5,
			expectedSuccess:    2,
			expected503:        3,
			serverDelay:        100 * time.Millisecond,
		},
		{
			name:               "limit to 5 connections",
			maxConnections:     5,
			concurrentRequests: 10,
			expectedSuccess:    5,
			expected503:        5,
			serverDelay:        50 * time.Millisecond,
		},
		{
			name:               "no limit (0 means no limiting)",
			maxConnections:     0,
			concurrentRequests: 10,
			expectedSuccess:    10,
			expected503:        0,
			serverDelay:        10 * time.Millisecond,
		},
		{
			name:               "single connection",
			maxConnections:     1,
			concurrentRequests: 3,
			expectedSuccess:    1,
			expected503:        2,
			serverDelay:        50 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(tt.serverDelay)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))
			defer server.Close()

			baseTransport := &http.Transport{}
			defer baseTransport.CloseIdleConnections()

			// Create connection limiter
			limiter := transport.NewConnectionLimiter(baseTransport, tt.maxConnections)
			client := &http.Client{
				Transport: limiter,
				Timeout:   5 * time.Second,
			}

			// Make concurrent requests
			var wg sync.WaitGroup
			responses := make(chan *http.Response, tt.concurrentRequests)
			errors := make(chan error, tt.concurrentRequests)

			for i := 0; i < tt.concurrentRequests; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					req, _ := http.NewRequest("GET", server.URL, nil)
					resp, err := client.Do(req)
					if err != nil {
						errors <- err
						return
					}
					responses <- resp
				}()
			}

			wg.Wait()
			close(responses)
			close(errors)

			// Count responses by status code
			statusCounts := make(map[int]int)
			for resp := range responses {
				statusCounts[resp.StatusCode]++
				resp.Body.Close()
			}

			// Check for errors
			for err := range errors {
				t.Errorf("unexpected error: %v", err)
			}

			successCount := statusCounts[200]
			serviceUnavailableCount := statusCounts[503]

			if successCount != tt.expectedSuccess {
				t.Errorf("expected %d successful requests, got %d", tt.expectedSuccess, successCount)
			}

			if serviceUnavailableCount != tt.expected503 {
				t.Errorf("expected %d 503 responses, got %d", tt.expected503, serviceUnavailableCount)
			}
		})
	}
}

// TestMaxRequestsHandlerWithErrorPages tests max requests handler with error pages
func TestMaxRequestsHandlerWithErrorPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	// Create connection limiter with limit of 2
	limiter := transport.NewConnectionLimiter(baseTransport, 2)
	client := &http.Client{
		Transport: limiter,
		Timeout:   5 * time.Second,
	}

	// Make 5 concurrent requests
	var wg sync.WaitGroup
	responses := make(chan *http.Response, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", server.URL, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			responses <- resp
		}()
	}

	wg.Wait()
	close(responses)

	// Count responses
	statusCounts := make(map[int]int)
	for resp := range responses {
		statusCounts[resp.StatusCode]++
		resp.Body.Close()
	}

	// Should have 2 successful (200) and 3 rejected (503)
	if statusCounts[200] != 2 {
		t.Errorf("expected 2 successful requests, got %d", statusCounts[200])
	}

	if statusCounts[503] != 3 {
		t.Errorf("expected 3 503 responses, got %d", statusCounts[503])
	}
}

// TestMaxRequestsHandlerActiveConnections tests active connection tracking
func TestMaxRequestsHandlerActiveConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	limiter := transport.NewConnectionLimiter(baseTransport, 3)
	cl := limiter.(*transport.ConnectionLimiter)

	client := &http.Client{
		Transport: limiter,
		Timeout:   5 * time.Second,
	}

	// Start 3 concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", server.URL, nil)
			client.Do(req)
		}()
	}

	// Wait a bit for requests to start
	time.Sleep(50 * time.Millisecond)

	// Check active connections
	activeCount := cl.GetActiveConnections()
	if activeCount != 3 {
		t.Errorf("expected 3 active connections, got %d", activeCount)
	}

	// Wait for all requests to complete
	wg.Wait()

	// Check that all connections are released
	activeCount = cl.GetActiveConnections()
	if activeCount != 0 {
		t.Errorf("expected 0 active connections after completion, got %d", activeCount)
	}

	// Verify max connections
	maxConnections := cl.GetMaxConnections()
	if maxConnections != 3 {
		t.Errorf("expected max connections to be 3, got %d", maxConnections)
	}
}

// TestMaxRequestsHandlerWaitForAllConnections tests graceful shutdown functionality
func TestMaxRequestsHandlerWaitForAllConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	limiter := transport.NewConnectionLimiter(baseTransport, 2)
	cl := limiter.(*transport.ConnectionLimiter)

	client := &http.Client{
		Transport: limiter,
		Timeout:   5 * time.Second,
	}

	// Start 2 concurrent requests
	var wg sync.WaitGroup
	started := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started <- struct{}{}
			req, _ := http.NewRequest("GET", server.URL, nil)
			client.Do(req)
		}()
	}

	// Ensure both requests have started
	<-started
	<-started

	// Wait for all connections to complete
	cl.WaitForAllConnections()

	// Check that all connections are released
	activeCount := cl.GetActiveConnections()
	if activeCount != 0 {
		t.Errorf("expected 0 active connections after WaitForAllConnections, got %d", activeCount)
	}

	wg.Wait()
}

// TestMaxRequestsHandlerWaitForAllConnectionsWithTimeout tests timeout functionality
func TestMaxRequestsHandlerWaitForAllConnectionsWithTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	baseTransport := &http.Transport{}
	defer baseTransport.CloseIdleConnections()

	limiter := transport.NewConnectionLimiter(baseTransport, 2)
	cl := limiter.(*transport.ConnectionLimiter)

	client := &http.Client{
		Transport: limiter,
		Timeout:   5 * time.Second,
	}

	// Start 2 concurrent requests
	var wg sync.WaitGroup
	started := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started <- struct{}{}
			req, _ := http.NewRequest("GET", server.URL, nil)
			client.Do(req)
		}()
	}

	// Ensure both requests have started
	<-started
	<-started

	// Wait with timeout that should succeed
	success := cl.WaitForAllConnectionsWithTimeout(500 * time.Millisecond)
	if !success {
		t.Error("expected WaitForAllConnectionsWithTimeout to succeed")
	}

	// Test with timeout that should fail
	// Start a new request that takes longer than timeout
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	req, _ := http.NewRequest("GET", slowServer.URL, nil)
	go client.Do(req)

	// Wait a bit for request to start
	time.Sleep(10 * time.Millisecond)

	// Wait with short timeout
	success = cl.WaitForAllConnectionsWithTimeout(50 * time.Millisecond)
	if success {
		t.Error("expected WaitForAllConnectionsWithTimeout to timeout")
	}

	wg.Wait()
}
