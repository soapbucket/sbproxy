package requestlimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNew_ValidConfig verifies that valid configs create an enforcer.
func TestNew_ValidConfig(t *testing.T) {
	cfg := Config{
		Type: "request_limiting",
		SizeLimits: &SizeLimitsConfig{
			MaxURLLength: 2000,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if enforcer == nil {
		t.Fatal("expected non-nil enforcer")
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
	cfg := Config{Type: "request_limiting"}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rl := enforcer.(*requestLimitPolicy)
	if rl.Type() != "request_limiting" {
		t.Errorf("expected type 'request_limiting', got %q", rl.Type())
	}
}

// TestEnforce_Disabled verifies that disabled policy passes through.
func TestEnforce_Disabled(t *testing.T) {
	cfg := Config{
		Type:     "request_limiting",
		Disabled: true,
		SizeLimits: &SizeLimitsConfig{
			MaxURLLength: 1,
		},
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

	req := httptest.NewRequest(http.MethodGet, "/very/long/url/that/exceeds/limit", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called when policy is disabled")
	}
}

// TestEnforce_URLTooLong verifies URL length check.
func TestEnforce_URLTooLong(t *testing.T) {
	cfg := Config{
		Type: "request_limiting",
		SizeLimits: &SizeLimitsConfig{
			MaxURLLength: 10,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/very/long/url/path/that/exceeds/limit", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("expected next handler NOT to be called for URL exceeding limit")
	}
	if w.Code != http.StatusRequestURITooLong {
		t.Errorf("expected 414, got %d", w.Code)
	}
}

// TestEnforce_QueryStringTooLong verifies query string length check.
func TestEnforce_QueryStringTooLong(t *testing.T) {
	cfg := Config{
		Type: "request_limiting",
		SizeLimits: &SizeLimitsConfig{
			MaxQueryStringLength: 5,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/?key=very_long_value_that_exceeds", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("expected next handler NOT to be called for query string exceeding limit")
	}
	if w.Code != http.StatusRequestURITooLong {
		t.Errorf("expected 414, got %d", w.Code)
	}
}

// TestEnforce_TooManyHeaders verifies header count check.
func TestEnforce_TooManyHeaders(t *testing.T) {
	cfg := Config{
		Type: "request_limiting",
		SizeLimits: &SizeLimitsConfig{
			MaxHeadersCount: 2,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Custom-1", "value1")
	req.Header.Set("X-Custom-2", "value2")
	req.Header.Set("X-Custom-3", "value3")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("expected next handler NOT to be called for too many headers")
	}
	if w.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("expected 431, got %d", w.Code)
	}
}

// TestEnforce_RequestBodyTooLarge verifies body size check.
func TestEnforce_RequestBodyTooLarge(t *testing.T) {
	cfg := Config{
		Type: "request_limiting",
		SizeLimits: &SizeLimitsConfig{
			MaxRequestSize: "10B",
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := enforcer.Enforce(next)

	body := strings.NewReader("this body is definitely larger than 10 bytes")
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("expected next handler NOT to be called for body exceeding limit")
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", w.Code)
	}
}

// TestEnforce_PassesWithinLimits verifies requests within limits pass through.
func TestEnforce_PassesWithinLimits(t *testing.T) {
	cfg := Config{
		Type: "request_limiting",
		SizeLimits: &SizeLimitsConfig{
			MaxURLLength:    1000,
			MaxHeadersCount: 50,
			MaxRequestSize:  "1MB",
		},
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

	req := httptest.NewRequest(http.MethodGet, "/short", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called for request within limits")
	}
}

// TestParseSize verifies size string parsing.
func TestParseSize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
		wantErr  bool
	}{
		{"bytes", "100B", 100, false},
		{"kilobytes", "10KB", 10 * 1024, false},
		{"megabytes", "5MB", 5 * 1024 * 1024, false},
		{"gigabytes", "1GB", 1024 * 1024 * 1024, false},
		{"terabytes", "2TB", 2 * 1024 * 1024 * 1024 * 1024, false},
		{"no unit", "500", 500, false},
		{"empty string", "", 0, false},
		{"invalid unit", "100XB", 0, true},
		{"no number", "MB", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSize(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Errorf("parseSize(%q) = %d, want %d", tc.input, got, tc.expected)
			}
		})
	}
}

// TestEnforce_ComplexityLimits_NestedDepth verifies JSON nesting depth check.
func TestEnforce_ComplexityLimits_NestedDepth(t *testing.T) {
	cfg := Config{
		Type: "request_limiting",
		ComplexityLimits: &ComplexityLimitsConfig{
			MaxNestedDepth: 2,
		},
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := enforcer.Enforce(next)

	// JSON with nesting depth > 2
	deepJSON := `{"a":{"b":{"c":{"d":"too deep"}}}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(deepJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("expected next handler NOT to be called for deeply nested JSON")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
