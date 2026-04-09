package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/soapbucket/sbproxy/internal/config/waf"
)

// TestWAFPolicyWithE2EConfig tests WAF policy with the actual E2E config
func TestWAFPolicyWithE2EConfig(t *testing.T) {
	// Load the actual E2E config
	configJSON := `{
		"waf.test": {
			"id": "waf",
			"hostname": "waf.test",
			"workspace_id": "test-workspace",
			"policies": [
				{
					"type": "waf",
					"custom_rules": [
						{
							"id": "block-sql-injection",
							"name": "Block SQL Injection",
							"disabled": false,
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
				"url": "http://e2e-test-server:8090"
			}
		}
	}`

	var rawConfig map[string]json.RawMessage
	if err := json.Unmarshal([]byte(configJSON), &rawConfig); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Use Load() function like configloader does
	cfg, err := Load(rawConfig["waf.test"])
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify WAF policy was loaded
	if len(cfg.policies) == 0 {
		t.Fatalf("Expected at least one policy, got %d", len(cfg.policies))
	}

	wafPolicy, ok := cfg.policies[0].(*WAFPolicyConfig)
	if !ok {
		t.Fatalf("Expected WAFPolicyConfig, got %T", cfg.policies[0])
	}

	// Verify rule was loaded
	if len(wafPolicy.CustomRules) == 0 {
		t.Fatalf("Expected at least one custom rule, got %d", len(wafPolicy.CustomRules))
	}

	rule := wafPolicy.CustomRules[0]
	t.Logf("Rule ID: %s", rule.ID)
	t.Logf("Rule Enabled: %v", rule.Enabled)
	t.Logf("Rule Disabled: %v", rule.Disabled)

	// Test 1: Verify rule is enabled after Init
	t.Run("Rule enabled after Init", func(t *testing.T) {
		// Init should already be called during Load, but verify rule is enabled
		// Note: Init is called during UnmarshalJSON, so rules should already be enabled

		// Check if rule engine was created
		if wafPolicy.ruleEngine == nil {
			t.Fatal("Rule engine is nil after Init")
		}

		// Check if rule is enabled
		// After Init, if Disabled=false, Enabled should be set to true
		if rule.Disabled {
			if rule.Enabled {
				t.Error("Rule should be disabled when Disabled=true")
			}
		} else {
			if !rule.Enabled {
				t.Errorf("Rule should be enabled when Disabled=false. Enabled=%v, Disabled=%v", rule.Enabled, rule.Disabled)
			}
		}
	})

	// Test 2: Test WAF blocking SQL injection
	t.Run("WAF blocks SQL injection", func(t *testing.T) {
		// Policy should already be initialized during Load

		// Create a request with SQL injection
		reqURL, _ := url.Parse("http://waf.test/?id=1%27%20OR%20%271")
		req := httptest.NewRequest("GET", reqURL.String(), nil)

		// Create a response recorder
		w := httptest.NewRecorder()

		// Create a handler that should be blocked
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If this is called, request was not blocked
			w.WriteHeader(http.StatusOK)
		})

		// Apply WAF policy
		wafHandler := wafPolicy.Apply(nextHandler)

		// Execute the request
		wafHandler.ServeHTTP(w, req)

		// Check if request was blocked
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d. Body: %s", w.Code, w.Body.String())
			t.Logf("Request was not blocked - WAF policy may not be working correctly")
			
			// Debug: Check rule engine
			if wafPolicy.ruleEngine == nil {
				t.Error("Rule engine is nil")
			} else {
				// Manually evaluate rules
				matches, err := wafPolicy.ruleEngine.EvaluateRequest(req.Context(), req)
				if err != nil {
					t.Errorf("Error evaluating rules: %v", err)
				} else {
					t.Logf("Rule evaluation matches: %d", len(matches))
					if len(matches) > 0 {
						t.Logf("Match details: %+v", matches[0])
					}
				}
			}
		} else {
			t.Logf("✓ Request was correctly blocked with status 403")
		}
	})

	// Test 3: Test WAF allows normal requests
	t.Run("WAF allows normal requests", func(t *testing.T) {
		// Policy should already be initialized during Load

		// Create a normal request
		reqURL, _ := url.Parse("http://waf.test/?id=123")
		req := httptest.NewRequest("GET", reqURL.String(), nil)

		// Create a response recorder
		w := httptest.NewRecorder()

		// Create a handler that should be called
		called := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		// Apply WAF policy
		wafHandler := wafPolicy.Apply(nextHandler)

		// Execute the request
		wafHandler.ServeHTTP(w, req)

		// Check if request was allowed
		if !called {
			t.Error("Expected next handler to be called for normal request")
		}
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	// Test 4: Test rule engine directly
	t.Run("Rule engine evaluation", func(t *testing.T) {
		// Policy should already be initialized during Load

		if wafPolicy.ruleEngine == nil {
			t.Fatal("Rule engine is nil")
		}

		// Test SQL injection
		reqURL, _ := url.Parse("http://waf.test/?id=1%27%20OR%20%271")
		req := httptest.NewRequest("GET", reqURL.String(), nil)

		matches, err := wafPolicy.ruleEngine.EvaluateRequest(req.Context(), req)
		if err != nil {
			t.Fatalf("Error evaluating rules: %v", err)
		}

		if len(matches) == 0 {
			t.Error("Expected rule to match SQL injection pattern, but no matches found")
			t.Logf("Query string: %s", reqURL.RawQuery)
			t.Logf("Query values: %v", reqURL.Query())
			
			// Check what variables are extracted
			if len(wafPolicy.CustomRules) > 0 {
				rule := wafPolicy.CustomRules[0]
				values := waf.ExtractVariables(req, rule.Variables[0])
				t.Logf("Extracted ARGS values: %v", values)
				
				// Check transformations
				if len(values) > 0 {
					transformed := waf.ApplyTransformations(values[0], rule.Transformations)
					t.Logf("Transformed value: %s", transformed)
					t.Logf("Pattern: %s", rule.Pattern)
					t.Logf("Rule Enabled: %v", rule.Enabled)
				}
			}
		} else {
			t.Logf("✓ Rule matched: %+v", matches[0])
		}
	})
}

