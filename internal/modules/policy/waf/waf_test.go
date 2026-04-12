package waf

import (
	"encoding/json"
	"testing"
)

// TestNew_ValidConfig verifies that a valid config creates an enforcer.
func TestNew_ValidConfig(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"waf"}`))
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
	enforcer, err := New(json.RawMessage(`{"type":"waf"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wp := enforcer.(*wafPolicy)
	if wp.Type() != "waf" {
		t.Errorf("expected type 'waf', got %q", wp.Type())
	}
}

// TestNew_WithOptions verifies config parsing with various options.
func TestNew_WithOptions(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "disabled",
			json: `{"type":"waf","disabled":true}`,
		},
		{
			name: "test mode",
			json: `{"type":"waf","test_mode":true}`,
		},
		{
			name: "fail open",
			json: `{"type":"waf","fail_open":true}`,
		},
		{
			name: "with default action",
			json: `{"type":"waf","default_action":"block"}`,
		},
		{
			name: "with execution time",
			json: `{"type":"waf","max_rule_execution_time":"5s"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enforcer, err := New(json.RawMessage(tc.json))
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if enforcer == nil {
				t.Fatal("expected non-nil enforcer")
			}
		})
	}
}
