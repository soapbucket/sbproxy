package config

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func TestFallbackOrigin_ShouldTriggerOnError(t *testing.T) {
	tests := []struct {
		name     string
		fallback *FallbackOrigin
		err      error
		expected bool
	}{
		{
			name:     "nil fallback",
			fallback: nil,
			err:      errors.New("connection refused"),
			expected: false,
		},
		{
			name:     "nil error",
			fallback: &FallbackOrigin{OnError: true},
			err:      nil,
			expected: false,
		},
		{
			name:     "on_error connection refused",
			fallback: &FallbackOrigin{OnError: true},
			err:      errors.New("connection refused"),
			expected: true,
		},
		{
			name:     "on_error TLS error",
			fallback: &FallbackOrigin{OnError: true},
			err:      errors.New("TLS handshake failure"),
			expected: true,
		},
		{
			name:     "on_error certificate error",
			fallback: &FallbackOrigin{OnError: true},
			err:      errors.New("certificate verification failed"),
			expected: true,
		},
		{
			name:     "on_error unhealthy backend",
			fallback: &FallbackOrigin{OnError: true},
			err:      errors.New("backend is unhealthy"),
			expected: true,
		},
		{
			name:     "on_error DNS failure",
			fallback: &FallbackOrigin{OnError: true},
			err:      errors.New("DNS resolution failed"),
			expected: true,
		},
		{
			name:     "on_error broken pipe",
			fallback: &FallbackOrigin{OnError: true},
			err:      errors.New("broken pipe"),
			expected: true,
		},
		{
			name:     "on_error connection reset",
			fallback: &FallbackOrigin{OnError: true},
			err:      errors.New("connection reset by peer"),
			expected: true,
		},
		{
			name:     "on_timeout deadline exceeded",
			fallback: &FallbackOrigin{OnTimeout: true},
			err:      errors.New("context deadline exceeded"),
			expected: true,
		},
		{
			name:     "on_timeout timeout",
			fallback: &FallbackOrigin{OnTimeout: true},
			err:      errors.New("i/o timeout"),
			expected: true,
		},
		{
			name:     "on_error disabled does not match connection error",
			fallback: &FallbackOrigin{OnError: false, OnTimeout: true},
			err:      errors.New("connection refused"),
			expected: false,
		},
		{
			name:     "on_timeout disabled does not match timeout",
			fallback: &FallbackOrigin{OnError: true, OnTimeout: false},
			err:      errors.New("context deadline exceeded"),
			expected: false,
		},
		{
			name:     "unrecognized error with on_error",
			fallback: &FallbackOrigin{OnError: true},
			err:      errors.New("some random error"),
			expected: false,
		},
		{
			name:     "both enabled timeout triggers",
			fallback: &FallbackOrigin{OnError: true, OnTimeout: true},
			err:      errors.New("request timeout"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fallback.ShouldTriggerOnError(tt.err)
			if result != tt.expected {
				t.Errorf("ShouldTriggerOnError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFallbackOrigin_ShouldTriggerOnStatus(t *testing.T) {
	tests := []struct {
		name       string
		fallback   *FallbackOrigin
		statusCode int
		expected   bool
	}{
		{
			name:       "nil fallback",
			fallback:   nil,
			statusCode: 502,
			expected:   false,
		},
		{
			name:       "empty on_status",
			fallback:   &FallbackOrigin{},
			statusCode: 502,
			expected:   false,
		},
		{
			name:       "matching status 502",
			fallback:   &FallbackOrigin{OnStatus: []int{502, 503, 504}},
			statusCode: 502,
			expected:   true,
		},
		{
			name:       "matching status 503",
			fallback:   &FallbackOrigin{OnStatus: []int{502, 503, 504}},
			statusCode: 503,
			expected:   true,
		},
		{
			name:       "non-matching status 404",
			fallback:   &FallbackOrigin{OnStatus: []int{502, 503, 504}},
			statusCode: 404,
			expected:   false,
		},
		{
			name:       "non-matching status 200",
			fallback:   &FallbackOrigin{OnStatus: []int{502, 503, 504}},
			statusCode: 200,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fallback.ShouldTriggerOnStatus(tt.statusCode)
			if result != tt.expected {
				t.Errorf("ShouldTriggerOnStatus(%d) = %v, want %v", tt.statusCode, result, tt.expected)
			}
		})
	}
}

func TestFallbackOrigin_MatchesRequest(t *testing.T) {
	tests := []struct {
		name     string
		fallback *FallbackOrigin
		method   string
		path     string
		expected bool
	}{
		{
			name:     "nil fallback",
			fallback: nil,
			method:   "GET",
			path:     "/api/test",
			expected: false,
		},
		{
			name:     "no rules matches all",
			fallback: &FallbackOrigin{Hostname: "fallback.internal"},
			method:   "GET",
			path:     "/anything",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			result := tt.fallback.MatchesRequest(req)
			if result != tt.expected {
				t.Errorf("MatchesRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFallbackOrigin_HasEmbeddedOrigin(t *testing.T) {
	tests := []struct {
		name     string
		fallback *FallbackOrigin
		expected bool
	}{
		{
			name:     "nil fallback",
			fallback: nil,
			expected: false,
		},
		{
			name:     "empty origin",
			fallback: &FallbackOrigin{},
			expected: false,
		},
		{
			name:     "embedded origin set",
			fallback: &FallbackOrigin{Origin: []byte(`{"id":"inline","action":{"type":"proxy","url":"http://localhost"}}`)},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fallback.HasEmbeddedOrigin()
			if result != tt.expected {
				t.Errorf("HasEmbeddedOrigin() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Benchmarks

func BenchmarkFallbackOrigin_ShouldTriggerOnError(b *testing.B) {
	b.ReportAllocs()
	f := &FallbackOrigin{OnError: true, OnTimeout: true}
	err := errors.New("connection refused")
	for i := 0; i < b.N; i++ {
		_ = f.ShouldTriggerOnError(err)
	}
}

func BenchmarkFallbackOrigin_ShouldTriggerOnStatus(b *testing.B) {
	b.ReportAllocs()
	f := &FallbackOrigin{OnStatus: []int{502, 503, 504}}
	for i := 0; i < b.N; i++ {
		_ = f.ShouldTriggerOnStatus(502)
	}
}

func BenchmarkFallbackOrigin_MatchesRequest_NoRules(b *testing.B) {
	b.ReportAllocs()
	f := &FallbackOrigin{Hostname: "fallback.internal"}
	req := httptest.NewRequest("GET", "/api/test", nil)
	for i := 0; i < b.N; i++ {
		_ = f.MatchesRequest(req)
	}
}
