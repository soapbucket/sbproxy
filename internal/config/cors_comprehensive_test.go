package config

import (
	"encoding/json"
	"testing"
)

// TestCORSComprehensiveConfiguration tests that CORS comprehensive configuration
// uses response_modifiers instead of a "cors" policy type (which doesn't exist)
func TestCORSComprehensiveConfiguration(t *testing.T) {
	configJSON := `{
		"id": "cors-comprehensive",
		"hostname": "cors-comprehensive.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		},
		"response_modifiers": [
			{
				"headers": {
					"set": {
						"Access-Control-Allow-Origin": "https://example.com",
						"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
						"Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
						"Access-Control-Expose-Headers": "X-Total-Count, X-Page-Count",
						"Access-Control-Max-Age": "3600",
						"Access-Control-Allow-Credentials": "true"
					}
				}
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
		t.Error("IsProxy() should return true for CORS comprehensive configuration")
	}

	// Verify Transport() is not nil
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil")
	}

	t.Logf("Successfully loaded CORS comprehensive configuration")
	t.Logf("Config ID: %s", cfg.ID)
	t.Logf("Hostname: %s", cfg.Hostname)
}

// TestCORSPolicyTypeDoesNotExist verifies that "cors" policy type doesn't exist
// This documents that CORS should be handled via response_modifiers, not policies
func TestCORSPolicyTypeDoesNotExist(t *testing.T) {
	configJSON := `{
		"id": "cors-policy-test",
		"hostname": "cors-policy.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		},
		"policies": [
			{
				"type": "cors",
				"enabled": true
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err == nil {
		t.Error("Expected error for unknown policy type 'cors', but got none")
	} else if err.Error() != "unknown policy type: cors" {
		t.Errorf("Expected 'unknown policy type: cors', got: %v", err)
	} else {
		t.Logf("Correctly rejected 'cors' policy type: %v", err)
	}
}

