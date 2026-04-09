package lua

import (
	"net/http"
	"testing"
)

func TestNewCircuitBreakerFn(t *testing.T) {
	script := `
function should_break_circuit(status, error, ctx)
  return status >= 500
end
`

	cb, err := NewCircuitBreakerFn(script)
	if err != nil {
		t.Fatalf("NewCircuitBreakerFn failed: %v", err)
	}

	if cb == nil {
		t.Fatal("NewCircuitBreakerFn returned nil")
	}
}

func TestCircuitBreakerFnMissingFunction(t *testing.T) {
	script := `
-- Missing should_break_circuit function
local x = 1
`

	_, err := NewCircuitBreakerFn(script)
	if err == nil {
		t.Fatal("Expected error for missing function, got nil")
	}

	if err.Error() != "lua: missing required function 'should_break_circuit' in circuit breaker script" {
		t.Fatalf("Unexpected error message: %v", err)
	}
}

func TestCircuitBreakerFnShouldBreak(t *testing.T) {
	script := `
function should_break_circuit(status, error, ctx)
  -- Break on 5xx errors
  return status >= 500
end
`

	cb, err := NewCircuitBreakerFn(script)
	if err != nil {
		t.Fatalf("NewCircuitBreakerFn failed: %v", err)
	}

	tests := []struct {
		status   int
		error    string
		expected bool
	}{
		{500, "Internal Server Error", true},
		{502, "Bad Gateway", true},
		{503, "Service Unavailable", true},
		{404, "Not Found", false},
		{200, "", false},
		{400, "Bad Request", false},
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	for _, tt := range tests {
		result := cb.ShouldBreak(tt.status, tt.error, req)
		if result != tt.expected {
			t.Fatalf("ShouldBreak(%d, %q) = %v, want %v", tt.status, tt.error, result, tt.expected)
		}
	}
}

func TestCircuitBreakerFnWithContext(t *testing.T) {
	script := `
function should_break_circuit(status, error, ctx)
  -- Only break for non-US users on 5xx errors
  local is_us = ctx.location and ctx.location.country_code == "US"
  if is_us then
    return status >= 503  -- More lenient for US
  else
    return status >= 500  -- Stricter for non-US
  end
end
`

	cb, err := NewCircuitBreakerFn(script)
	if err != nil {
		t.Fatalf("NewCircuitBreakerFn failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	// Without location context, should use non-US rules (status >= 500)
	result := cb.ShouldBreak(500, "Internal Server Error", req)
	if !result {
		t.Fatal("Expected true for 500 error without location, got false")
	}
}

func TestCircuitBreakerFnErrorHandling(t *testing.T) {
	script := `
function should_break_circuit(status, error, ctx)
  -- Script that returns non-boolean (should still work due to type conversion)
  if status >= 500 then
    return true
  end
  return false
end
`

	cb, err := NewCircuitBreakerFn(script)
	if err != nil {
		t.Fatalf("NewCircuitBreakerFn failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	result := cb.ShouldBreak(500, "error", req)
	if !result {
		t.Fatal("Expected true for 500 error, got false")
	}
}

func TestCircuitBreakerFnNilError(t *testing.T) {
	script := `
function should_break_circuit(status, error, ctx)
  -- Handle nil error
  if error == nil or error == "" then
    return status >= 500
  end
  return true
end
`

	cb, err := NewCircuitBreakerFn(script)
	if err != nil {
		t.Fatalf("NewCircuitBreakerFn failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	// Pass empty string for error
	result := cb.ShouldBreak(500, "", req)
	if !result {
		t.Fatal("Expected true for 500 error with nil error, got false")
	}
}
