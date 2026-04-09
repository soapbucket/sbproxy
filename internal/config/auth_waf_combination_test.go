package config

import (
	"encoding/json"
	"testing"
)

// TestAuthPlusWAFCombination tests the auth+WAF combination from fixture 85
// This reproduces the issue where auth-waf.test returns 404
func TestAuthPlusWAFCombination(t *testing.T) {
	// This is the exact config from test/fixtures/origins/85-auth-plus-waf.json
	configJSON := `{
		"id": "auth-waf",
		"hostname": "auth-waf.test",
		"authentication": {
			"type": "basic_auth",
			"disabled": false,
			"users": [
				{
					"username": "testuser",
					"password": "testpass"
				}
			]
		},
		"policies": [
			{
				"type": "waf",
				"custom_rules": [
					{
						"id": "block-sql-injection",
						"name": "Block SQL Injection",
						"enabled": true,
						"phase": 2,
						"severity": "critical",
						"action": "block",
						"variables": [
							{
								"name": "ARGS",
								"collection": "ARGS"
							}
						],
						"operator": "rx",
						"pattern": "(?i)(union|select|insert|delete|update|drop|create|alter|or|and)",
						"transformations": ["lowercase", "urlDecode"]
					}
				],
				"default_action": "log",
				"action_on_match": "block"
			}
		],
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090/api/headers"
		}
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify the config is a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for auth+waf combination")
	}

	// Verify Transport() is not nil
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil")
	}

	// Verify Rewrite() is not nil
	rewriteFn := cfg.Rewrite()
	if rewriteFn == nil {
		t.Error("Rewrite() should not return nil for proxy action")
	}

	// The actual action type is internal and accessed via methods
	// We can verify it works by checking IsProxy() and Transport()
	t.Logf("Config successfully loaded for auth+WAF combination")
	t.Logf("IsProxy: %v", cfg.IsProxy())
	t.Logf("Has Transport: %v", transport != nil)
	t.Logf("Has Rewrite: %v", rewriteFn != nil)
}

