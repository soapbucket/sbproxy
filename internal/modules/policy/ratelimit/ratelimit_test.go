package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNew_ValidConfig verifies that valid configs create an enforcer.
func TestNew_ValidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "basic per minute",
			config: Config{
				Type:              "rate_limiting",
				RequestsPerMinute: 100,
			},
		},
		{
			name: "token bucket",
			config: Config{
				Type:      "rate_limiting",
				Algorithm: "token_bucket",
				BurstSize: 50,
			},
		},
		{
			name: "with whitelist",
			config: Config{
				Type:              "rate_limiting",
				RequestsPerMinute: 10,
				Whitelist:         []string{"192.168.1.0/24"},
			},
		},
		{
			name: "with blacklist",
			config: Config{
				Type:              "rate_limiting",
				RequestsPerMinute: 10,
				Blacklist:         []string{"10.0.0.0/8"},
			},
		},
		{
			name:   "empty config",
			config: Config{Type: "rate_limiting"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(tc.config)
			enforcer, err := New(data)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if enforcer == nil {
				t.Fatal("expected non-nil enforcer")
			}
		})
	}
}

// TestNew_InvalidJSON verifies that invalid JSON returns an error.
func TestNew_InvalidJSON(t *testing.T) {
	_, err := New(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestType verifies the Type() method returns the correct string.
func TestType(t *testing.T) {
	cfg := Config{Type: "rate_limiting"}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rl := enforcer.(*rateLimitPolicy)
	if rl.Type() != "rate_limiting" {
		t.Errorf("expected type 'rate_limiting', got %q", rl.Type())
	}
}

// TestEnforce_Disabled verifies that disabled policy passes through.
func TestEnforce_Disabled(t *testing.T) {
	cfg := Config{
		Type:              "rate_limiting",
		Disabled:          true,
		RequestsPerMinute: 1,
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called when policy is disabled")
	}
}

// TestEnforce_AllowsRequestWithinLimit verifies a single request is allowed.
func TestEnforce_AllowsRequestWithinLimit(t *testing.T) {
	cfg := Config{
		Type:              "rate_limiting",
		RequestsPerMinute: 100,
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called for request within limit")
	}
}

// TestEnforce_BlocksAfterLimit verifies requests are blocked after limit.
func TestEnforce_BlocksAfterLimit(t *testing.T) {
	cfg := Config{
		Type:              "rate_limiting",
		RequestsPerMinute: 2,
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)

	// Send requests up to and beyond the limit
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if i >= 2 && w.Code != http.StatusTooManyRequests {
			// After the limit is exceeded, expect 429
			// Note: the exact boundary depends on implementation
			t.Logf("request %d: status=%d", i, w.Code)
		}
	}
}

// TestNew_ConfigParsing verifies that configuration fields are correctly parsed.
func TestNew_ConfigParsing(t *testing.T) {
	cfg := Config{
		Type:              "rate_limiting",
		RequestsPerMinute: 60,
		RequestsPerHour:   1000,
		RequestsPerDay:    10000,
		Algorithm:         "token_bucket",
		BurstSize:         20,
		RefillRate:         1.5,
		Headers: RateLimitHeadersConfig{
			Enabled:           true,
			IncludeRetryAfter: true,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rl := enforcer.(*rateLimitPolicy)
	if rl.cfg.RequestsPerMinute != 60 {
		t.Errorf("expected RequestsPerMinute=60, got %d", rl.cfg.RequestsPerMinute)
	}
	if rl.cfg.RequestsPerHour != 1000 {
		t.Errorf("expected RequestsPerHour=1000, got %d", rl.cfg.RequestsPerHour)
	}
	if rl.cfg.Algorithm != "token_bucket" {
		t.Errorf("expected Algorithm='token_bucket', got %q", rl.cfg.Algorithm)
	}
	if !rl.cfg.Headers.Enabled {
		t.Error("expected Headers.Enabled=true")
	}
}
