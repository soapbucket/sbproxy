package lua

import (
	"net/http"
	"testing"
)

func TestNewRateLimitAdjuster(t *testing.T) {
	script := `
function adjust_rate_limit(req, ctx)
  return {
    requests_per_minute = 60,
    burst_size = 10
  }
end
`

	adj, err := NewRateLimitAdjuster(script)
	if err != nil {
		t.Fatalf("NewRateLimitAdjuster failed: %v", err)
	}

	if adj == nil {
		t.Fatal("NewRateLimitAdjuster returned nil")
	}
}

func TestAdjustRateLimitMissingFunction(t *testing.T) {
	script := `
-- Missing adjust_rate_limit function
local x = 1
`

	_, err := NewRateLimitAdjuster(script)
	if err == nil {
		t.Fatal("Expected error for missing function, got nil")
	}

	if err.Error() != "lua: missing required function 'adjust_rate_limit'" {
		t.Fatalf("Unexpected error message: %v", err)
	}
}

func TestAdjustRateLimits(t *testing.T) {
	script := `
function adjust_rate_limit(req, ctx)
  return {
    requests_per_minute = 120,
    requests_per_hour = 5000,
    burst_size = 20
  }
end
`

	adj, err := NewRateLimitAdjuster(script)
	if err != nil {
		t.Fatalf("NewRateLimitAdjuster failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	limits, err := adj.AdjustRateLimits(req)
	if err != nil {
		t.Fatalf("AdjustRateLimits failed: %v", err)
	}

	if limits == nil {
		t.Fatal("Expected limits, got nil")
	}

	if limits.RequestsPerMinute != 120 {
		t.Fatalf("Expected 120, got %d", limits.RequestsPerMinute)
	}

	if limits.RequestsPerHour != 5000 {
		t.Fatalf("Expected 5000, got %d", limits.RequestsPerHour)
	}

	if limits.BurstSize != 20 {
		t.Fatalf("Expected 20, got %d", limits.BurstSize)
	}
}

func TestAdjustRateLimitsPartialFields(t *testing.T) {
	script := `
function adjust_rate_limit(req, ctx)
  -- Only return some fields
  return {
    requests_per_minute = 100
  }
end
`

	adj, err := NewRateLimitAdjuster(script)
	if err != nil {
		t.Fatalf("NewRateLimitAdjuster failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	limits, err := adj.AdjustRateLimits(req)
	if err != nil {
		t.Fatalf("AdjustRateLimits failed: %v", err)
	}

	if limits == nil {
		t.Fatal("Expected limits, got nil")
	}

	if limits.RequestsPerMinute != 100 {
		t.Fatalf("Expected 100, got %d", limits.RequestsPerMinute)
	}
}

func TestAdjustRateLimitsReturnsNil(t *testing.T) {
	script := `
function adjust_rate_limit(req, ctx)
  return nil  -- No adjustment
end
`

	adj, err := NewRateLimitAdjuster(script)
	if err != nil {
		t.Fatalf("NewRateLimitAdjuster failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	limits, err := adj.AdjustRateLimits(req)
	if err != nil {
		t.Fatalf("AdjustRateLimits failed: %v", err)
	}

	if limits != nil {
		t.Fatalf("Expected nil, got %v", limits)
	}
}

func TestAdjustRateLimitsEmptyTable(t *testing.T) {
	script := `
function adjust_rate_limit(req, ctx)
  return {}  -- Empty table
end
`

	adj, err := NewRateLimitAdjuster(script)
	if err != nil {
		t.Fatalf("NewRateLimitAdjuster failed: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/api", nil)
	limits, err := adj.AdjustRateLimits(req)
	if err != nil {
		t.Fatalf("AdjustRateLimits failed: %v", err)
	}

	if limits != nil {
		t.Fatalf("Expected nil for empty table, got %v", limits)
	}
}
