package config

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestWAFMiddlewareIntegration tests the full WAF middleware chain
// This simulates how the config is loaded and applied in the actual proxy
func TestWAFMiddlewareIntegration(t *testing.T) {
	// Load config exactly as configloader does
	configJSON := `{
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
	}`

	// Load config using Load() function (same as configloader)
	cfg, err := Load([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify WAF policy was loaded and initialized
	if len(cfg.policies) == 0 {
		t.Fatalf("Expected at least one policy, got %d", len(cfg.policies))
	}

	wafPolicy, ok := cfg.policies[0].(*WAFPolicyConfig)
	if !ok {
		t.Fatalf("Expected WAFPolicyConfig, got %T", cfg.policies[0])
	}

	// Verify rule engine was initialized
	if wafPolicy.ruleEngine == nil {
		t.Fatal("Rule engine is nil after Load() - Init() may not have been called")
	}

	// Verify rules are enabled
	if len(wafPolicy.CustomRules) == 0 {
		t.Fatal("No custom rules found")
	}

	rule := wafPolicy.CustomRules[0]
	if !rule.Enabled {
		t.Errorf("Rule should be enabled. Enabled=%v, Disabled=%v", rule.Enabled, rule.Disabled)
	}

	t.Logf("✓ Config loaded successfully")
	t.Logf("  - Policy type: %s", wafPolicy.GetType())
	t.Logf("  - Custom rules: %d", len(wafPolicy.CustomRules))
	t.Logf("  - Rule engine initialized: %v", wafPolicy.ruleEngine != nil)
	t.Logf("  - Rule enabled: %v", rule.Enabled)

	// Test 1: SQL injection should be blocked
	t.Run("SQL injection blocked", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=1%27%20OR%20%271")
		req := httptest.NewRequest("GET", reqURL.String(), nil)
		w := httptest.NewRecorder()

		// Create next handler (should not be called if WAF blocks)
		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		// Apply WAF middleware
		wafHandler := wafPolicy.Apply(nextHandler)

		// Execute request
		wafHandler.ServeHTTP(w, req)

		// Verify request was blocked
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d. Body: %s", w.Code, w.Body.String())
			t.Logf("Next handler called: %v", nextCalled)
			
			// Debug: Check rule engine state
			if wafPolicy.ruleEngine == nil {
				t.Error("Rule engine is nil in Apply()")
			} else {
				// Manually evaluate to see what's happening
				matches, err := wafPolicy.ruleEngine.EvaluateRequest(req.Context(), req)
				t.Logf("Manual evaluation - matches: %d, error: %v", len(matches), err)
				if len(matches) > 0 {
					t.Logf("Match details: %+v", matches[0])
				}
			}
		} else {
			t.Logf("✓ Request correctly blocked with 403")
			if nextCalled {
				t.Error("Next handler should not be called when request is blocked")
			}
		}
	})

	// Test 2: Normal request should pass through
	t.Run("Normal request allowed", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=123")
		req := httptest.NewRequest("GET", reqURL.String(), nil)
		w := httptest.NewRecorder()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		wafHandler := wafPolicy.Apply(nextHandler)
		wafHandler.ServeHTTP(w, req)

		if !nextCalled {
			t.Error("Next handler should be called for normal request")
		}
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	// Test 3: Test with Config.ServeHTTP (full middleware chain)
	t.Run("Full middleware chain", func(t *testing.T) {
		// Create a request with SQL injection
		reqURL, _ := url.Parse("http://waf.test/?id=1%27%20OR%20%271")
		req := httptest.NewRequest("GET", reqURL.String(), nil)
		req.Host = "waf.test"
		w := httptest.NewRecorder()

		// Use Config.ServeHTTP which applies all middleware
		cfg.ServeHTTP(w, req)

		// Verify request was blocked
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403 from full middleware chain, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ Full middleware chain correctly blocked request")
		}
	})
}

// TestWAFPolicyInitCalled tests that Init is called during config loading
func TestWAFPolicyInitCalled(t *testing.T) {
	configJSON := `{
		"id": "waf",
		"hostname": "waf.test",
		"workspace_id": "test-workspace",
		"policies": [
			{
				"type": "waf",
				"custom_rules": [
					{
						"id": "test-rule",
						"disabled": false,
						"variables": [{"name": "ARGS", "collection": "ARGS"}],
						"operator": "rx",
						"pattern": "test"
					}
				],
				"action_on_match": "block"
			}
		],
		"action": {"type": "proxy", "url": "http://test:8090"}
	}`

	cfg, err := Load([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.policies) == 0 {
		t.Fatal("No policies loaded")
	}

	wafPolicy, ok := cfg.policies[0].(*WAFPolicyConfig)
	if !ok {
		t.Fatalf("Expected WAFPolicyConfig, got %T", cfg.policies[0])
	}

	// Verify Init was called (rule engine should be initialized)
	if wafPolicy.ruleEngine == nil {
		t.Error("Rule engine is nil - Init() was not called or failed")
	} else {
		t.Logf("✓ Rule engine initialized: %v rules", len(wafPolicy.CustomRules))
	}

	// Verify rules are enabled
	if len(wafPolicy.CustomRules) > 0 {
		rule := wafPolicy.CustomRules[0]
		if !rule.Enabled {
			t.Errorf("Rule should be enabled after Init. Enabled=%v, Disabled=%v", rule.Enabled, rule.Disabled)
		}
	}
}

// TestWAFPolicyWithDisabledRule tests that disabled rules are not evaluated
func TestWAFPolicyWithDisabledRule(t *testing.T) {
	configJSON := `{
		"id": "waf",
		"hostname": "waf.test",
		"workspace_id": "test-workspace",
		"policies": [
			{
				"type": "waf",
				"custom_rules": [
					{
						"id": "disabled-rule",
						"disabled": true,
						"variables": [{"name": "ARGS", "collection": "ARGS"}],
						"operator": "rx",
						"pattern": ".*"
					}
				],
				"action_on_match": "block"
			}
		],
		"action": {"type": "proxy", "url": "http://test:8090"}
	}`

	cfg, err := Load([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	wafPolicy := cfg.policies[0].(*WAFPolicyConfig)
	rule := wafPolicy.CustomRules[0]

	if rule.Enabled {
		t.Error("Rule should be disabled when disabled=true")
	}

	// Request should pass through since rule is disabled
	reqURL, _ := url.Parse("http://waf.test/?test=anything")
	req := httptest.NewRequest("GET", reqURL.String(), nil)
	w := httptest.NewRecorder()

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wafHandler := wafPolicy.Apply(nextHandler)
	wafHandler.ServeHTTP(w, req)

	if !nextCalled {
		t.Error("Next handler should be called when rule is disabled")
	}
}

