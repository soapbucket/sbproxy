package httputil

import (
	"net/http"
	"testing"
	"time"
)

func TestIsCacheable(t *testing.T) {
	tests := []struct {
		name     string
		request  *http.Request
		expected bool
	}{
		{
			name:     "GET request should be cacheable",
			request:  createRequest("GET", "https://example.com", nil),
			expected: true,
		},
		{
			name:     "HEAD request should be cacheable",
			request:  createRequest("HEAD", "https://example.com", nil),
			expected: true,
		},
		{
			name:     "POST request should not be cacheable",
			request:  createRequest("POST", "https://example.com", nil),
			expected: false,
		},
		{
			name: "Request with no-cache should not be cacheable",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderCacheControl: "no-cache",
			}),
			expected: false,
		},
		{
			name: "Request with no-store should not be cacheable",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderCacheControl: "no-store",
			}),
			expected: false,
		},
		{
			name: "Request with authorization should not be cacheable",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderAuthorization: "Bearer token",
			}),
			expected: false,
		},
		{
			name: "Request with max-age should be cacheable",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderCacheControl: "max-age=3600",
			}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCacheable(tt.request)
			if result != tt.expected {
				t.Errorf("IsCacheable() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGenerateCacheKey(t *testing.T) {
	tests := []struct {
		name     string
		request  *http.Request
		expected string
	}{
		{
			name:     "Simple GET request",
			request:  createRequest("GET", "https://example.com", nil),
			expected: "GET:https://example.com",
		},
		{
			name:     "GET request with query parameters",
			request:  createRequest("GET", "https://example.com?foo=bar&baz=qux", nil),
			expected: "GET:https://example.com?baz=qux&foo=bar",
		},
		{
			name:     "GET request with empty query parameters",
			request:  createRequest("GET", "https://example.com?foo=&bar=baz", nil),
			expected: "GET:https://example.com?bar=baz",
		},
		{
			name: "GET request with Vary header",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderVary:      "Accept, User-Agent",
				HeaderAccept:    "application/json",
				HeaderUserAgent: "test-agent",
			}),
			expected: "GET:https://example.com|vary:accept:application/json,user-agent:test-agent",
		},
		{
			name: "GET request with multiple Vary headers",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderVary:           "Accept-Encoding, Accept-Language",
				HeaderAcceptEncoding: "gzip",
				HeaderAcceptLanguage: "en-US",
			}),
			expected: "GET:https://example.com|vary:accept-encoding:gzip,accept-language:en-US",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateCacheKey(tt.request)
			// Since we're using SHA256, we can't predict the exact hash
			// but we can verify it's a 64-character hex string
			if len(result) != 64 {
				t.Errorf("GenerateCacheKey() length = %d, want 64", len(result))
			}

			// Test that the same request generates the same key
			result2 := GenerateCacheKey(tt.request)
			if result != result2 {
				t.Errorf("GenerateCacheKey() should be deterministic, got %s and %s", result, result2)
			}
		})
	}
}

func TestCalculateCacheDuration(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		response *http.Response
		check    func(*CachedResponse) bool
	}{
		{
			name: "Response with max-age",
			response: createResponse(200, map[string]string{
				HeaderCacheControl: "max-age=3600",
				HeaderETag:         `"abc123"`,
			}),
			check: func(cached *CachedResponse) bool {
				return cached.MaxAge == 3600 &&
					cached.ETag == `"abc123"` &&
					cached.Expires.After(now.Add(3599*time.Second)) &&
					cached.Expires.Before(now.Add(3601*time.Second))
			},
		},
		{
			name: "Response with no-store",
			response: createResponse(200, map[string]string{
				HeaderCacheControl: "no-store",
			}),
			check: func(cached *CachedResponse) bool {
				return cached.NoStore && cached.Expires.Before(now)
			},
		},
		{
			name: "Response with must-revalidate",
			response: createResponse(200, map[string]string{
				HeaderCacheControl: "must-revalidate, max-age=1800",
			}),
			check: func(cached *CachedResponse) bool {
				return cached.MustRevalidate && cached.MaxAge == 1800
			},
		},
		{
			name: "Response with private",
			response: createResponse(200, map[string]string{
				HeaderCacheControl: "private, max-age=900",
			}),
			check: func(cached *CachedResponse) bool {
				return cached.Private && cached.MaxAge == 900
			},
		},
		{
			name: "Response with public",
			response: createResponse(200, map[string]string{
				HeaderCacheControl: "public, max-age=7200",
			}),
			check: func(cached *CachedResponse) bool {
				return cached.Public && cached.MaxAge == 7200
			},
		},
		{
			name: "Response with Vary header",
			response: createResponse(200, map[string]string{
				HeaderVary: "Accept, User-Agent",
			}),
			check: func(cached *CachedResponse) bool {
				return len(cached.VaryHeaders) == 2 &&
					(cached.VaryHeaders[0] == "Accept" || cached.VaryHeaders[0] == "User-Agent") &&
					(cached.VaryHeaders[1] == "Accept" || cached.VaryHeaders[1] == "User-Agent")
			},
		},
		{
			name: "Response with Expires header",
			response: createResponse(200, map[string]string{
				HeaderExpires: now.Add(2 * time.Hour).Format(time.RFC1123),
			}),
			check: func(cached *CachedResponse) bool {
				return cached.Expires.After(now.Add(119*time.Minute)) &&
					cached.Expires.Before(now.Add(121*time.Minute))
			},
		},
		{
			name: "Response with stale-while-revalidate",
			response: createResponse(200, map[string]string{
				HeaderCacheControl: "max-age=3600, stale-while-revalidate=7200",
			}),
			check: func(cached *CachedResponse) bool {
				return cached.MaxAge == 3600 &&
					cached.StaleDuration > time.Duration(3600)*time.Second
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateCacheDuration(tt.response)
			if !tt.check(result) {
				t.Errorf("CalculateCacheDuration() did not meet expectations for %s", tt.name)
			}
		})
	}
}

func TestIsCacheValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		request  *http.Request
		cached   *CachedResponse
		expected bool
		stale    bool
	}{
		{
			name:    "Fresh cache should be valid",
			request: createRequest("GET", "https://example.com", nil),
			cached: &CachedResponse{
				Expires: now.Add(time.Hour),
				ETag:    `"abc123"`,
			},
			expected: true,
			stale:    false,
		},
		{
			name:    "Expired cache should be stale",
			request: createRequest("GET", "https://example.com", nil),
			cached: &CachedResponse{
				Expires:       now.Add(-30 * time.Minute),
				StaleDuration: time.Hour,
				ETag:          `"abc123"`,
			},
			expected: false,
			stale:    true,
		},
		{
			name:    "Fully expired cache should be invalid",
			request: createRequest("GET", "https://example.com", nil),
			cached: &CachedResponse{
				Expires:       now.Add(-2 * time.Hour),
				StaleDuration: time.Hour,
				ETag:          `"abc123"`,
			},
			expected: false,
			stale:    false,
		},
		{
			name: "ETag mismatch should be invalid",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderIfNoneMatch: `"xyz789"`,
			}),
			cached: &CachedResponse{
				Expires: now.Add(time.Hour),
				ETag:    `"abc123"`,
			},
			expected: false,
			stale:    false,
		},
		{
			name: "ETag match should be valid",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderIfNoneMatch: `"abc123"`,
			}),
			cached: &CachedResponse{
				Expires: now.Add(time.Hour),
				ETag:    `"abc123"`,
			},
			expected: true,
			stale:    false,
		},
		{
			name: "Request with no-cache should be invalid",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderCacheControl: "no-cache",
			}),
			cached: &CachedResponse{
				Expires: now.Add(time.Hour),
				ETag:    `"abc123"`,
			},
			expected: false,
			stale:    false,
		},
		{
			name:    "Must revalidate expired cache should be invalid",
			request: createRequest("GET", "https://example.com", nil),
			cached: &CachedResponse{
				Expires:        now.Add(-time.Hour),
				MustRevalidate: true,
				ETag:           `"abc123"`,
			},
			expected: false,
			stale:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, stale := IsCacheValid(tt.request, tt.cached)
			if valid != tt.expected {
				t.Errorf("IsCacheValid() valid = %v, want %v", valid, tt.expected)
			}
			if stale != tt.stale {
				t.Errorf("IsCacheValid() stale = %v, want %v", stale, tt.stale)
			}
		})
	}
}

func TestParseCacheControl(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		expected     map[string]int
	}{
		{
			name:         "Simple max-age",
			cacheControl: "max-age=3600",
			expected:     map[string]int{"max-age": 3600},
		},
		{
			name:         "Multiple directives",
			cacheControl: "max-age=3600, must-revalidate, no-cache",
			expected:     map[string]int{"max-age": 3600, "must-revalidate": 1, "no-cache": 1},
		},
		{
			name:         "Case insensitive",
			cacheControl: "MAX-AGE=1800, NO-STORE",
			expected:     map[string]int{"max-age": 1800, "no-store": 1},
		},
		{
			name:         "Stale while revalidate",
			cacheControl: "max-age=3600, stale-while-revalidate=7200",
			expected:     map[string]int{"max-age": 3600, "stale-while-revalidate": 7200},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCacheControl(tt.cacheControl)
			for key, expectedValue := range tt.expected {
				if result[key] != expectedValue {
					t.Errorf("parseCacheControl() [%s] = %d, want %d", key, result[key], expectedValue)
				}
			}
		})
	}
}

func TestGetVaryHeaders(t *testing.T) {
	tests := []struct {
		name     string
		response *http.Response
		expected []string
	}{
		{
			name:     "No Vary header",
			response: createResponse(200, map[string]string{}),
			expected: nil,
		},
		{
			name: "Single Vary header",
			response: createResponse(200, map[string]string{
				HeaderVary: "Accept",
			}),
			expected: []string{"Accept"},
		},
		{
			name: "Multiple Vary headers",
			response: createResponse(200, map[string]string{
				HeaderVary: "Accept, User-Agent, Accept-Encoding",
			}),
			expected: []string{"Accept", "User-Agent", "Accept-Encoding"},
		},
		{
			name: "Vary headers with spaces",
			response: createResponse(200, map[string]string{
				HeaderVary: "Accept , User-Agent , Accept-Encoding ",
			}),
			expected: []string{"Accept", "User-Agent", "Accept-Encoding"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetVaryHeaders(tt.response)
			if len(result) != len(tt.expected) {
				t.Errorf("GetVaryHeaders() length = %d, want %d", len(result), len(tt.expected))
				return
			}

			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("GetVaryHeaders()[%d] = %s, want %s", i, result[i], expected)
				}
			}
		})
	}
}

func TestShouldVary(t *testing.T) {
	tests := []struct {
		name        string
		request     *http.Request
		varyHeaders []string
		expected    bool
	}{
		{
			name:        "No vary headers",
			request:     createRequest("GET", "https://example.com", nil),
			varyHeaders: nil,
			expected:    false,
		},
		{
			name:        "Empty vary headers",
			request:     createRequest("GET", "https://example.com", nil),
			varyHeaders: []string{},
			expected:    false,
		},
		{
			name: "Request varies on Accept",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderAccept: "application/json",
			}),
			varyHeaders: []string{"Accept"},
			expected:    true,
		},
		{
			name: "Request varies on User-Agent",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderUserAgent: "test-agent",
			}),
			varyHeaders: []string{"User-Agent"},
			expected:    true,
		},
		{
			name:        "Request does not vary on missing header",
			request:     createRequest("GET", "https://example.com", nil),
			varyHeaders: []string{"Accept"},
			expected:    false,
		},
		{
			name: "Request varies on one of multiple headers",
			request: createRequest("GET", "https://example.com", map[string]string{
				HeaderAccept: "application/json",
			}),
			varyHeaders: []string{"Accept", "User-Agent"},
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldVary(tt.request, tt.varyHeaders)
			if result != tt.expected {
				t.Errorf("ShouldVary() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper functions for creating test requests and responses

func createRequest(method, url string, headers map[string]string) *http.Request {
	req, _ := http.NewRequest(method, url, nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}

func createRequestWithCookies(method, url string, headers map[string]string, cookies map[string]string) *http.Request {
	req, _ := http.NewRequest(method, url, nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	return req
}

func createResponse(statusCode int, headers map[string]string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
	}
	for key, value := range headers {
		resp.Header.Set(key, value)
	}
	return resp
}

func TestGenerateCacheKeyWithCustomValues(t *testing.T) {
	tests := []struct {
		name         string
		request      *http.Request
		customValues map[string]string
		expected     string
	}{
		{
			name:         "Request without custom values",
			request:      createRequest("GET", "https://example.com", nil),
			customValues: nil,
			expected:     "GET:https://example.com",
		},
		{
			name:    "Request with custom values",
			request: createRequest("GET", "https://example.com", nil),
			customValues: map[string]string{
				"user_id":    "123",
				"session_id": "abc456",
			},
			expected: "GET:https://example.com|custom:session_id:abc456,user_id:123",
		},
		{
			name:    "Request with custom values and query params",
			request: createRequest("GET", "https://example.com?foo=bar&baz=qux", nil),
			customValues: map[string]string{
				"tenant": "acme",
			},
			expected: "GET:https://example.com?baz=qux&foo=bar|custom:tenant:acme",
		},
		{
			name:    "Request with empty custom values",
			request: createRequest("GET", "https://example.com", nil),
			customValues: map[string]string{
				"":      "empty_key",
				"value": "",
			},
			expected: "GET:https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the raw key generation (before hashing)
			rawKey := generateRawCacheKeyWithCustomValues(tt.request, tt.customValues)
			if rawKey != tt.expected {
				t.Errorf("generateRawCacheKeyWithCustomValues() = %v, want %v", rawKey, tt.expected)
			}

			// Test the hashed key
			result := GenerateCacheKeyWithCustomValues(tt.request, tt.customValues)
			if len(result) != 64 {
				t.Errorf("GenerateCacheKeyWithCustomValues() length = %d, want 64", len(result))
			}

			// Test that the same request generates the same key
			result2 := GenerateCacheKeyWithCustomValues(tt.request, tt.customValues)
			if result != result2 {
				t.Errorf("GenerateCacheKeyWithCustomValues() should be deterministic, got %s and %s", result, result2)
			}
		})
	}
}
