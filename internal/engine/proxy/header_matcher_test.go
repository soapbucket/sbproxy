package proxy

import (
	"net/http"
	"testing"
)

func TestHeaderMatcher_ExactMatch(t *testing.T) {
	matcher := NewHeaderMatcher([]string{"X-Internal-Token", "X-Debug-Mode"})

	tests := []struct {
		header   string
		expected bool
	}{
		{"X-Internal-Token", true},
		{"X-Debug-Mode", true},
		{"x-internal-token", true}, // Case insensitive
		{"X-Public-Header", false},
		{"Authorization", false},
	}

	for _, tt := range tests {
		result := matcher.Matches(tt.header)
		if result != tt.expected {
			t.Errorf("header %s: expected %v, got %v", tt.header, tt.expected, result)
		}
	}
}

func TestHeaderMatcher_WildcardMatch(t *testing.T) {
	matcher := NewHeaderMatcher([]string{"X-Internal-*", "X-Debug-*"})

	tests := []struct {
		header   string
		expected bool
	}{
		{"X-Internal-Token", true},
		{"X-Internal-Anything", true},
		{"X-Debug-Mode", true},
		{"X-Debug-Trace", true},
		{"x-internal-foo", true}, // Case insensitive
		{"X-Public-Header", false},
		{"Authorization", false},
	}

	for _, tt := range tests {
		result := matcher.Matches(tt.header)
		if result != tt.expected {
			t.Errorf("header %s: expected %v, got %v", tt.header, tt.expected, result)
		}
	}
}

func TestHeaderMatcher_StripMatchingHeaders(t *testing.T) {
	matcher := NewHeaderMatcher([]string{"X-Internal-*", "X-Debug"})

	headers := http.Header{
		"X-Internal-Token": []string{"secret"},
		"X-Internal-Debug": []string{"true"},
		"X-Debug":          []string{"verbose"},
		"X-Public-Header":  []string{"value"},
		"Authorization":    []string{"Bearer token"},
		"Content-Type":     []string{"application/json"},
	}

	matcher.StripMatchingHeaders(headers)

	// Check that matched headers were removed
	if headers.Get("X-Internal-Token") != "" {
		t.Error("X-Internal-Token should be removed")
	}
	if headers.Get("X-Internal-Debug") != "" {
		t.Error("X-Internal-Debug should be removed")
	}
	if headers.Get("X-Debug") != "" {
		t.Error("X-Debug should be removed")
	}

	// Check that non-matched headers remain
	if headers.Get("X-Public-Header") == "" {
		t.Error("X-Public-Header should remain")
	}
	if headers.Get("Authorization") == "" {
		t.Error("Authorization should remain")
	}
	if headers.Get("Content-Type") == "" {
		t.Error("Content-Type should remain")
	}
}

func TestHeaderMatcher_EmptyPatterns(t *testing.T) {
	matcher := NewHeaderMatcher([]string{})

	headers := http.Header{
		"X-Internal-Token": []string{"secret"},
		"Authorization":    []string{"Bearer token"},
	}

	matcher.StripMatchingHeaders(headers)

	// Nothing should be removed
	if headers.Get("X-Internal-Token") == "" {
		t.Error("X-Internal-Token should remain")
	}
	if headers.Get("Authorization") == "" {
		t.Error("Authorization should remain")
	}
}
