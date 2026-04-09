package lua

import (
	"net/http"
	"testing"
)

func TestNewRouteMatcher(t *testing.T) {
	script := `
function select_route(req, ctx)
  return req.method == "GET"
end
`

	m, err := NewRouteMatcher(script)
	if err != nil {
		t.Fatalf("NewRouteMatcher failed: %v", err)
	}

	if m == nil {
		t.Fatal("NewRouteMatcher returned nil")
	}
}

func TestRouteMatcherMissingFunction(t *testing.T) {
	script := `
-- Missing select_route function
local x = 1
`

	_, err := NewRouteMatcher(script)
	if err == nil {
		t.Fatal("Expected error for missing function, got nil")
	}

	if err.Error() != "lua: missing required function 'select_route' in route matcher script" {
		t.Fatalf("Unexpected error message: %v", err)
	}
}

func TestRouteMatcherMatch(t *testing.T) {
	script := `
function select_route(req, ctx)
  return req.method == "GET" and string.find(req.path, "/api") ~= nil
end
`

	m, err := NewRouteMatcher(script)
	if err != nil {
		t.Fatalf("NewRouteMatcher failed: %v", err)
	}

	tests := []struct {
		method   string
		path     string
		expected bool
	}{
		{"GET", "/api/users", true},
		{"POST", "/api/users", false},
		{"GET", "/static/file", false},
		{"PUT", "/api/users/1", false},
	}

	for _, tt := range tests {
		req, _ := http.NewRequest(tt.method, "http://example.com"+tt.path, nil)
		result := m.Match(req)
		if result != tt.expected {
			t.Fatalf("Match(%s %s) = %v, want %v", tt.method, tt.path, result, tt.expected)
		}
	}
}

// TestRouteMatcherHeaderNormalization verifies that Lua headers are stored
// under lowercase keys only. Matches HTTP/2 convention.
func TestRouteMatcherHeaderNormalization(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		expected bool
	}{
		{
			name: "lowercase key x-admin matches",
			script: `
function select_route(req, ctx)
  return req.headers["x-admin"] == "true"
end`,
			expected: true,
		},
		{
			name: "original casing X-Admin does not match",
			script: `
function select_route(req, ctx)
  return req.headers["X-Admin"] == "true"
end`,
			expected: false,
		},
		{
			name: "underscore form x_admin does not match",
			script: `
function select_route(req, ctx)
  return req.headers["x_admin"] == "true"
end`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewRouteMatcher(tt.script)
			if err != nil {
				t.Fatalf("NewRouteMatcher failed: %v", err)
			}
			req, _ := http.NewRequest("GET", "http://example.com/test", nil)
			req.Header.Set("X-Admin", "true")
			result := m.Match(req)
			if result != tt.expected {
				t.Errorf("Match() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRouteMatcherWithContext(t *testing.T) {
	script := `
function select_route(req, ctx)
  -- Route to this target only for US users
  return ctx.location and ctx.location.country_code == "US"
end
`

	m, err := NewRouteMatcher(script)
	if err != nil {
		t.Fatalf("NewRouteMatcher failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	result := m.Match(req)
	// Without location info, should return false
	if result {
		t.Fatal("Expected false for missing location, got true")
	}
}
