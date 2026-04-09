package config

import (
	"net/http"
	"net/url"
	"testing"
)

func TestURINormalization_DotSegments(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/./users", "/api/users"},
		{"/api/../other", "/other"},
		{"/api/users/", "/api/users/"},
		{"/", "/"},
	}

	cfg := &URINormalizationConfig{Enable: true}

	for _, tt := range tests {
		r := &http.Request{
			Method: "GET",
		}
		r.URL = mustParseURL(tt.input)

		normalizeRequestURI(r, cfg)

		if r.URL.Path != tt.expected {
			t.Errorf("normalizeRequestURI(%q) = %q, want %q", tt.input, r.URL.Path, tt.expected)
		}
	}
}

func TestURINormalization_MergeSlashes(t *testing.T) {
	cfg := &URINormalizationConfig{Enable: true}

	r := &http.Request{Method: "GET"}
	r.URL = mustParseURL("/api//users///profile")

	normalizeRequestURI(r, cfg)

	if r.URL.Path != "/api/users/profile" {
		t.Errorf("expected /api/users/profile, got %s", r.URL.Path)
	}
}

func TestURINormalization_DecodeUnreserved(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/%7Euser", "/api/~user"},     // ~ is unreserved
		{"/api/%41%42", "/api/AB"},          // A, B are unreserved
		{"/api/%2F", "/api/%2F"},            // / is reserved, keep encoded
		{"/api/%20", "/api/%20"},            // space is not unreserved
	}

	for _, tt := range tests {
		result := decodeUnreservedChars(tt.input)
		if result != tt.expected {
			t.Errorf("decodeUnreservedChars(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestURINormalization_Disabled(t *testing.T) {
	r := &http.Request{Method: "GET"}
	r.URL = mustParseURL("/api//users")

	normalizeRequestURI(r, nil)

	if r.URL.Path != "/api//users" {
		t.Error("should not normalize when config is nil")
	}

	normalizeRequestURI(r, &URINormalizationConfig{Enable: false})
	if r.URL.Path != "/api//users" {
		t.Error("should not normalize when disabled")
	}
}

func TestMergeSlashes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"//", "/"},
		{"/a//b///c", "/a/b/c"},
		{"/normal/path", "/normal/path"},
		{"///", "/"},
	}

	for _, tt := range tests {
		result := mergeSlashes(tt.input)
		if result != tt.expected {
			t.Errorf("mergeSlashes(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func mustParseURL(raw string) *url.URL {
	return &url.URL{Path: raw}
}
