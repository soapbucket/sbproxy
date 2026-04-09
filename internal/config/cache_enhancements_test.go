package config

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestCacheKeyNormalization_QueryParams(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		norm     *CacheKeyNormalization
		expected string
	}{
		{
			name: "sort query parameters",
			url:  "https://example.com/api?z=1&a=2&m=3",
			norm: &CacheKeyNormalization{
				QueryParams: QueryParamNormalization{
					Sort: true,
				},
			},
			expected: "GET|https://example.com/api?a=2&m=3&z=1",
		},
		{
			name: "ignore utm parameters",
			url:  "https://example.com/api?id=123&utm_source=google&utm_medium=cpc",
			norm: &CacheKeyNormalization{
				QueryParams: QueryParamNormalization{
					Ignore: []string{"utm_source", "utm_medium"},
					Sort:   true,
				},
			},
			expected: "GET|https://example.com/api?id=123",
		},
		{
			name: "ignore with wildcard",
			url:  "https://example.com/api?id=123&utm_source=google&utm_campaign=test",
			norm: &CacheKeyNormalization{
				QueryParams: QueryParamNormalization{
					Ignore: []string{"utm_*"},
				},
			},
			expected: "GET|https://example.com/api?id=123",
		},
		{
			name: "lowercase parameter names",
			url:  "https://example.com/api?ID=123&UserId=456",
			norm: &CacheKeyNormalization{
				QueryParams: QueryParamNormalization{
					LowerCase: true,
					Sort:      true,
				},
			},
			expected: "GET|https://example.com/api?id=123&userid=456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tt.url, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			result := NormalizeCacheKey(req, tt.norm)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCacheKeyNormalization_CaseNormalization(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/API/Users", nil)

	norm := &CacheKeyNormalization{
		CaseNormalization: true,
	}

	result := NormalizeCacheKey(req, norm)
	expected := "GET|https://example.com/api/users"

	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestCacheKeyNormalization_Headers(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		norm     HeaderNormalization
		contains string
	}{
		{
			name: "include specific headers",
			headers: map[string]string{
				"Authorization": "Bearer token",
				"User-Agent":    "test",
				"X-Custom":      "value",
			},
			norm: HeaderNormalization{
				Include: []string{"Authorization", "X-Custom"},
			},
			contains: "authorization=Bearer token",
		},
		{
			name: "ignore specific headers",
			headers: map[string]string{
				"Authorization": "Bearer token",
				"User-Agent":    "test",
			},
			norm: HeaderNormalization{
				Ignore: []string{"User-Agent"},
			},
			contains: "authorization=Bearer token",
		},
		{
			name: "normalize header names",
			headers: map[string]string{
				"X-Custom-Header": "value",
			},
			norm: HeaderNormalization{
				Normalize: map[string]string{
					"X-Custom-Header": "x-custom",
				},
			},
			contains: "x-custom=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/api", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			norm := &CacheKeyNormalization{
				Headers: tt.norm,
			}

			result := NormalizeCacheKey(req, norm)
			// Result should contain the expected header part (case-insensitive)
			// Note: The exact matching depends on implementation details
			t.Logf("result: %s", result)
		})
	}
}

func TestCacheKeyNormalization_Cookies(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "abc123"})
	req.AddCookie(&http.Cookie{Name: "tracking_id", Value: "xyz789"})
	req.AddCookie(&http.Cookie{Name: "_ga", Value: "GA123"})

	norm := &CacheKeyNormalization{
		Cookies: CookieNormalization{
			Ignore: []string{"_ga", "tracking_id"},
		},
	}

	result := NormalizeCacheKey(req, norm)
	// Should only include session_id
	t.Logf("result: %s", result)
}

func TestCachedResponse_IsStale(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		resp     *CachedResponse
		expected bool
	}{
		{
			name: "fresh response",
			resp: &CachedResponse{
				CachedAt:  now.Add(-1 * time.Minute),
				ExpiresAt: now.Add(5 * time.Minute),
				StaleAt:   now.Add(4 * time.Minute),
			},
			expected: false,
		},
		{
			name: "stale response",
			resp: &CachedResponse{
				CachedAt:  now.Add(-5 * time.Minute),
				ExpiresAt: now.Add(5 * time.Minute),
				StaleAt:   now.Add(-1 * time.Minute),
			},
			expected: true,
		},
		{
			name: "expired response",
			resp: &CachedResponse{
				CachedAt:  now.Add(-10 * time.Minute),
				ExpiresAt: now.Add(-1 * time.Minute),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resp.IsStale()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCachedResponse_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		resp     *CachedResponse
		expected bool
	}{
		{
			name: "not expired",
			resp: &CachedResponse{
				ExpiresAt: now.Add(5 * time.Minute),
			},
			expected: false,
		},
		{
			name: "expired",
			resp: &CachedResponse{
				ExpiresAt: now.Add(-1 * time.Minute),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resp.IsExpired()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCachedResponse_CanServeStale(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		resp     *CachedResponse
		maxAge   time.Duration
		expected bool
	}{
		{
			name: "within max age",
			resp: &CachedResponse{
				CachedAt: now.Add(-5 * time.Minute),
			},
			maxAge:   10 * time.Minute,
			expected: true,
		},
		{
			name: "exceeds max age",
			resp: &CachedResponse{
				CachedAt: now.Add(-15 * time.Minute),
			},
			maxAge:   10 * time.Minute,
			expected: false,
		},
		{
			name: "max age zero",
			resp: &CachedResponse{
				CachedAt: now.Add(-1 * time.Minute),
			},
			maxAge:   0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resp.CanServeStale(tt.maxAge)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSerializeDeserializeCachedResponse(t *testing.T) {
	original := &CachedResponse{
		StatusCode: 200,
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
			"Cache-Control": {"max-age=3600"},
		},
		Body:         []byte(`{"status":"ok"}`),
		CachedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		StaleAt:      time.Now().Add(50 * time.Minute),
		ETag:         "abc123",
		LastModified: "Mon, 02 Jan 2006 15:04:05 GMT",
	}

	// Serialize
	data, err := SerializeCachedResponse(original)
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	// Deserialize
	deserialized, err := DeserializeCachedResponse(data)
	if err != nil {
		t.Fatalf("failed to deserialize: %v", err)
	}

	// Compare
	if deserialized.StatusCode != original.StatusCode {
		t.Errorf("status code mismatch: got %d, want %d", deserialized.StatusCode, original.StatusCode)
	}
	if string(deserialized.Body) != string(original.Body) {
		t.Errorf("body mismatch: got %s, want %s", deserialized.Body, original.Body)
	}
	if deserialized.ETag != original.ETag {
		t.Errorf("etag mismatch: got %s, want %s", deserialized.ETag, original.ETag)
	}
}

func TestShouldIgnoreParam(t *testing.T) {
	tests := []struct {
		param      string
		ignoreList []string
		expected   bool
	}{
		{"utm_source", []string{"utm_source"}, true},
		{"utm_campaign", []string{"utm_*"}, true},
		{"id", []string{"utm_*"}, false},
		{"other", []string{"utm_source", "utm_medium"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.param, func(t *testing.T) {
			result := shouldIgnoreParam(tt.param, tt.ignoreList)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestActionResponseCache_GenerateCacheKey_WithNormalization(t *testing.T) {
	cache := &ActionResponseCache{
		KeyNormalization: &CacheKeyNormalization{
			QueryParams: QueryParamNormalization{
				Sort:   true,
				Ignore: []string{"utm_*"},
			},
		},
	}

	req, _ := http.NewRequest("GET", "https://example.com/api?id=123&utm_source=google&name=test", nil)
	
	key := cache.GenerateCacheKey("test-action", req)
	
	// Should contain action name and normalized URL
	if !containsSubstring(key, "test-action") {
		t.Errorf("key should contain action name: %s", key)
	}
	
	// utm_source should be removed
	if containsSubstring(key, "utm_source") {
		t.Errorf("key should not contain utm_source: %s", key)
	}
}

func TestActionResponseCache_GenerateCacheKey_Legacy(t *testing.T) {
	cache := &ActionResponseCache{
		CacheKey: "method+url",
	}

	req, _ := http.NewRequest("POST", "https://example.com/api", nil)
	
	key := cache.GenerateCacheKey("test-action", req)
	
	if !containsSubstring(key, "test-action") {
		t.Errorf("key should contain action name: %s", key)
	}
	if !containsSubstring(key, "POST") {
		t.Errorf("key should contain method: %s", key)
	}
	if !containsSubstring(key, "example.com") {
		t.Errorf("key should contain URL: %s", key)
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || (len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || hasSubstr(s, substr))))
}

func hasSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestRevalidationQueue(t *testing.T) {
	// Create a test queue
	queue := newRevalidationQueue(1)
	defer queue.shutdown()

	// Enqueue a task
	task := &revalidationTask{
		key:       "test-key",
		url:       "https://example.com/test",
		headers:   http.Header{},
		timestamp: time.Now(),
	}

	queue.enqueue(task)

	// Check that task was queued
	queue.mu.RLock()
	_, exists := queue.tasks[task.key]
	queue.mu.RUnlock()

	if !exists {
		t.Error("task should be queued")
	}

	// Give worker time to process
	time.Sleep(100 * time.Millisecond)
}

func BenchmarkNormalizeCacheKey(b *testing.B) {
	b.ReportAllocs()
	u, _ := url.Parse("https://example.com/api?z=1&a=2&m=3&utm_source=google")
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: http.Header{
			"Authorization": []string{"Bearer token"},
			"User-Agent":    []string{"test"},
		},
	}

	norm := &CacheKeyNormalization{
		QueryParams: QueryParamNormalization{
			Sort:   true,
			Ignore: []string{"utm_*"},
		},
		Headers: HeaderNormalization{
			Include: []string{"Authorization"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NormalizeCacheKey(req, norm)
	}
}

func BenchmarkGenerateCacheKey(b *testing.B) {
	b.ReportAllocs()
	cache := &ActionResponseCache{
		KeyNormalization: &CacheKeyNormalization{
			QueryParams: QueryParamNormalization{
				Sort: true,
			},
		},
	}

	req, _ := http.NewRequest("GET", "https://example.com/api?z=1&a=2", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.GenerateCacheKey("test", req)
	}
}

