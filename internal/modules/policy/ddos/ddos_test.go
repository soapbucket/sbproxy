package ddos

import (
	"encoding/json"
	"testing"
)

// TestNew_ValidConfig verifies that a valid config creates an enforcer.
func TestNew_ValidConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"type": "ddos_protection",
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
	cfg := map[string]interface{}{
		"type": "ddos_protection",
	}
	data, _ := json.Marshal(cfg)

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dp := enforcer.(*ddosPolicy)
	if dp.Type() != "ddos_protection" {
		t.Errorf("expected type 'ddos_protection', got %q", dp.Type())
	}
}

// TestNew_WithDetectionConfig verifies config parsing with detection settings.
func TestNew_WithDetectionConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"type":     "ddos_protection",
		"disabled": false,
		"detection": map[string]interface{}{
			"request_rate_threshold":    100,
			"connection_rate_threshold": 50,
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

// TestNew_Disabled verifies disabled config creates an enforcer.
func TestNew_Disabled(t *testing.T) {
	cfg := map[string]interface{}{
		"type":     "ddos_protection",
		"disabled": true,
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
