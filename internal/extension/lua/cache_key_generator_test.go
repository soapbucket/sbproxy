package lua

import (
	"net/http"
	"testing"
)

func TestNewCacheKeyGenerator(t *testing.T) {
	script := `
function generate_cache_key(req, ctx)
  return req.method .. ":" .. req.path
end
`

	gen, err := NewCacheKeyGenerator(script)
	if err != nil {
		t.Fatalf("NewCacheKeyGenerator failed: %v", err)
	}

	if gen == nil {
		t.Fatal("NewCacheKeyGenerator returned nil")
	}
}

func TestCacheKeyGeneratorMissingFunction(t *testing.T) {
	script := `
-- Missing generate_cache_key function
local x = 1
`

	_, err := NewCacheKeyGenerator(script)
	if err == nil {
		t.Fatal("Expected error for missing function, got nil")
	}

	if err.Error() != "lua: missing required function 'generate_cache_key' in cache key script" {
		t.Fatalf("Unexpected error message: %v", err)
	}
}

func TestCacheKeyGeneratorCompilationError(t *testing.T) {
	script := `
function generate_cache_key(req, ctx)
  return invalid lua syntax here {{{
end
`

	_, err := NewCacheKeyGenerator(script)
	if err == nil {
		t.Fatal("Expected error for syntax error, got nil")
	}

	if err.Error() != "lua: script compilation error: <string>:2: '{' expected near 'here'" {
		t.Logf("Error message: %v", err)
		// Don't fail on exact message since Lua error messages vary
	}
}

func TestGenerateCacheKey(t *testing.T) {
	script := `
function generate_cache_key(req, ctx)
  return req.method .. ":" .. req.path
end
`

	gen, err := NewCacheKeyGenerator(script)
	if err != nil {
		t.Fatalf("NewCacheKeyGenerator failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)
	key, err := gen.GenerateCacheKey(req)
	if err != nil {
		t.Fatalf("GenerateCacheKey failed: %v", err)
	}

	expected := "GET:/api/users"
	if key != expected {
		t.Fatalf("Expected key %q, got %q", expected, key)
	}
}

func TestGenerateCacheKeyWithContext(t *testing.T) {
	script := `
function generate_cache_key(req, ctx)
  -- Include country code in cache key
  local country = ctx.location and ctx.location.country_code or "US"
  return req.method .. ":" .. req.path .. ":" .. country
end
`

	gen, err := NewCacheKeyGenerator(script)
	if err != nil {
		t.Fatalf("NewCacheKeyGenerator failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)
	key, err := gen.GenerateCacheKey(req)
	if err != nil {
		t.Fatalf("GenerateCacheKey failed: %v", err)
	}

	// Should include "US" as default when location not available
	expected := "GET:/api/users:US"
	if key != expected {
		t.Fatalf("Expected key %q, got %q", expected, key)
	}
}

func TestGenerateCacheKeyReturnsNil(t *testing.T) {
	script := `
function generate_cache_key(req, ctx)
  return nil
end
`

	gen, err := NewCacheKeyGenerator(script)
	if err != nil {
		t.Fatalf("NewCacheKeyGenerator failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)
	key, err := gen.GenerateCacheKey(req)
	if err == nil {
		t.Fatal("Expected error when function returns nil, got nil")
	}

	if key != "" {
		t.Fatalf("Expected empty key, got %q", key)
	}
}

func TestGenerateCacheKeyReturnsWrongType(t *testing.T) {
	script := `
function generate_cache_key(req, ctx)
  return 123  -- Return number instead of string
end
`

	gen, err := NewCacheKeyGenerator(script)
	if err != nil {
		t.Fatalf("NewCacheKeyGenerator failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api/users", nil)
	key, err := gen.GenerateCacheKey(req)
	if err == nil {
		t.Fatal("Expected error when function returns wrong type, got nil")
	}

	if key != "" {
		t.Fatalf("Expected empty key, got %q", key)
	}
}
