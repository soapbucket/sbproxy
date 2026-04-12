package mcp

import (
	"testing"
	"time"
)

func TestNewToolRateLimiter(t *testing.T) {
	rl := NewToolRateLimiter(nil)
	if rl == nil {
		t.Fatal("expected non-nil ToolRateLimiter")
	}
}

func TestToolRateLimiter_NoLimit(t *testing.T) {
	rl := NewToolRateLimiter(nil)
	// No limits configured, should always allow
	for i := 0; i < 100; i++ {
		if !rl.Allow("any_tool", "user-1") {
			t.Fatal("expected Allow to return true with no limits")
		}
	}
}

func TestToolRateLimiter_ZeroLimit(t *testing.T) {
	rl := NewToolRateLimiter(map[string]*ToolRateLimitConfig{
		"search": {RequestsPerMinute: 0},
	})
	// Zero limit means no restriction
	if !rl.Allow("search", "user-1") {
		t.Fatal("expected Allow to return true with zero limit")
	}
}

func TestToolRateLimiter_BasicLimit(t *testing.T) {
	rl := NewToolRateLimiter(map[string]*ToolRateLimitConfig{
		"search": {RequestsPerMinute: 3},
	})

	// First 3 should succeed
	for i := 0; i < 3; i++ {
		if !rl.Allow("search", "user-1") {
			t.Fatalf("expected Allow to return true on call %d", i+1)
		}
	}

	// 4th should fail
	if rl.Allow("search", "user-1") {
		t.Fatal("expected Allow to return false after exceeding limit")
	}
}

func TestToolRateLimiter_PerConsumer(t *testing.T) {
	rl := NewToolRateLimiter(map[string]*ToolRateLimitConfig{
		"search": {RequestsPerMinute: 2},
	})

	// user-1 uses 2
	rl.Allow("search", "user-1")
	rl.Allow("search", "user-1")

	// user-1 should be blocked
	if rl.Allow("search", "user-1") {
		t.Fatal("expected user-1 to be rate limited")
	}

	// user-2 should still be allowed
	if !rl.Allow("search", "user-2") {
		t.Fatal("expected user-2 to be allowed (separate counter)")
	}
}

func TestToolRateLimiter_WindowReset(t *testing.T) {
	now := time.Now()
	rl := NewToolRateLimiter(map[string]*ToolRateLimitConfig{
		"search": {RequestsPerMinute: 1},
	})
	rl.nowFunc = func() time.Time { return now }

	// Use the single allowed request
	if !rl.Allow("search", "user-1") {
		t.Fatal("expected first call to be allowed")
	}

	// Should be blocked
	if rl.Allow("search", "user-1") {
		t.Fatal("expected second call to be blocked")
	}

	// Advance time past the window
	rl.nowFunc = func() time.Time { return now.Add(61 * time.Second) }

	// Should be allowed again
	if !rl.Allow("search", "user-1") {
		t.Fatal("expected call after window reset to be allowed")
	}
}

func TestToolRateLimiter_DifferentTools(t *testing.T) {
	rl := NewToolRateLimiter(map[string]*ToolRateLimitConfig{
		"search": {RequestsPerMinute: 1},
		"deploy": {RequestsPerMinute: 2},
	})

	// Use search's single allowance
	rl.Allow("search", "user-1")
	if rl.Allow("search", "user-1") {
		t.Fatal("expected search to be blocked")
	}

	// deploy should still have quota
	if !rl.Allow("deploy", "user-1") {
		t.Fatal("expected deploy to be allowed (different tool)")
	}
}

func TestToolRateLimiter_Remaining(t *testing.T) {
	rl := NewToolRateLimiter(map[string]*ToolRateLimitConfig{
		"search": {RequestsPerMinute: 5},
	})

	// No limit configured for this tool
	if r := rl.Remaining("unknown_tool", "user-1"); r != -1 {
		t.Errorf("expected -1 for unconfigured tool, got %d", r)
	}

	// Full quota available
	if r := rl.Remaining("search", "user-1"); r != 5 {
		t.Errorf("expected 5 remaining, got %d", r)
	}

	// Use 2
	rl.Allow("search", "user-1")
	rl.Allow("search", "user-1")

	if r := rl.Remaining("search", "user-1"); r != 3 {
		t.Errorf("expected 3 remaining, got %d", r)
	}
}

func TestToolRateLimiter_Remaining_WindowReset(t *testing.T) {
	now := time.Now()
	rl := NewToolRateLimiter(map[string]*ToolRateLimitConfig{
		"search": {RequestsPerMinute: 3},
	})
	rl.nowFunc = func() time.Time { return now }

	rl.Allow("search", "user-1")

	// Advance past window
	rl.nowFunc = func() time.Time { return now.Add(2 * time.Minute) }

	if r := rl.Remaining("search", "user-1"); r != 3 {
		t.Errorf("expected full quota after window reset, got %d", r)
	}
}
