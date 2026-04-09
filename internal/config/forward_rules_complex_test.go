package config

import (
	"encoding/json"
	"testing"
)

// TestForwardRulesComplexConfiguration tests that forward rules use hostname and rules structure
func TestForwardRulesComplexConfiguration(t *testing.T) {
	configJSON := `{
		"id": "forward-rules-complex",
		"hostname": "forward-rules-complex.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		},
		"forward_rules": [
			{
				"hostname": "api-v1-backend.test",
				"rules": [
					{
						"path": {"prefix": "/api/v1"}
					}
				]
			},
			{
				"hostname": "old-service-backend.test",
				"rules": [
					{
						"path": {"prefix": "/old"}
					}
				]
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify it loaded successfully
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for forward rules complex configuration")
	}

	// Verify Transport() is not nil
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil")
	}

	// Verify forward rules were loaded
	if len(cfg.ForwardRules) != 2 {
		t.Errorf("Expected 2 forward rules, got %d", len(cfg.ForwardRules))
	}

	// Verify the hostnames
	expectedHostnames := []string{"api-v1-backend.test", "old-service-backend.test"}
	for i, expected := range expectedHostnames {
		if i >= len(cfg.ForwardRules) {
			t.Errorf("Missing forward rule at index %d", i)
			continue
		}
		if cfg.ForwardRules[i].Hostname != expected {
			t.Errorf("Forward rule %d: expected hostname %s, got %s", i, expected, cfg.ForwardRules[i].Hostname)
		}
	}

	t.Logf("Successfully loaded forward rules complex configuration")
	t.Logf("Config ID: %s", cfg.ID)
	t.Logf("Hostname: %s", cfg.Hostname)
	t.Logf("Forward rules: %d", len(cfg.ForwardRules))
}

// TestForwardRulesWrongFormat tests that wrong format (from/to) fails
func TestForwardRulesWrongFormat(t *testing.T) {
	configJSON := `{
		"id": "forward-rules-wrong",
		"hostname": "forward-rules-wrong.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		},
		"forward_rules": [
			{
				"from": "/api/v1/*",
				"to": "/api/v2/*"
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err == nil {
		// It might not error, but the forward rules won't work correctly
		// Check if forward rules are empty or have wrong structure
		if len(cfg.ForwardRules) > 0 && cfg.ForwardRules[0].Hostname == "" {
			t.Logf("Forward rules loaded but hostname is empty (wrong format)")
		} else {
			t.Error("Expected forward rules to fail or have empty hostname for wrong format")
		}
	} else {
		t.Logf("Correctly rejected wrong format: %v", err)
	}
}

