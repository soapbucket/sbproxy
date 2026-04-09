package config

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/object"
)

// TestWAFCachedConfig tests that WAF works correctly when config is cached
func TestWAFCachedConfig(t *testing.T) {
	// Create a cache like configloader does
	cache, _ := objectcache.NewObjectCache(10*time.Minute, 1*time.Minute, 1000, 100*1024*1024)

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

	// First load - simulate loading from storage
	cfg1, err := Load([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify WAF policy is initialized
	if len(cfg1.policies) == 0 {
		t.Fatal("No policies loaded")
	}

	wafPolicy1 := cfg1.policies[0].(*WAFPolicyConfig)
	if wafPolicy1.ruleEngine == nil {
		t.Fatal("Rule engine is nil after first load")
	}

	if len(wafPolicy1.CustomRules) == 0 {
		t.Fatal("No custom rules")
	}

	rule1 := wafPolicy1.CustomRules[0]
	if !rule1.Enabled {
		t.Errorf("Rule should be enabled. Enabled=%v, Disabled=%v", rule1.Enabled, rule1.Disabled)
	}

	t.Logf("✓ First load successful")
	t.Logf("  - Rule engine initialized: %v", wafPolicy1.ruleEngine != nil)
	t.Logf("  - Rule enabled: %v", rule1.Enabled)

	// Cache the config
	cache.Put("waf.test", cfg1)

	// Second load - simulate loading from cache
	entry, ok := cache.Get("waf.test")
	if !ok {
		t.Fatal("Config not found in cache")
	}

	cfg2 := entry.(*Config)

	// Verify it's the same instance
	if cfg1 != cfg2 {
		t.Error("Expected same config instance from cache")
	}

	// Verify WAF policy still has rule engine
	wafPolicy2 := cfg2.policies[0].(*WAFPolicyConfig)
	if wafPolicy2.ruleEngine == nil {
		t.Fatal("Rule engine is nil in cached config - this is the bug!")
	}

	rule2 := wafPolicy2.CustomRules[0]
	if !rule2.Enabled {
		t.Errorf("Rule should be enabled in cached config. Enabled=%v, Disabled=%v", rule2.Enabled, rule2.Disabled)
	}

	t.Logf("✓ Cached config verified")
	t.Logf("  - Rule engine initialized: %v", wafPolicy2.ruleEngine != nil)
	t.Logf("  - Rule enabled: %v", rule2.Enabled)

	// Test that WAF still blocks with cached config
	t.Run("WAF blocks with cached config", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=1%27%20OR%20%271")
		req := httptest.NewRequest("GET", reqURL.String(), nil)
		w := httptest.NewRecorder()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		wafHandler := wafPolicy2.Apply(nextHandler)
		wafHandler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403 with cached config, got %d. Body: %s", w.Code, w.Body.String())
			t.Logf("Next handler called: %v", nextCalled)
			t.Logf("Rule engine nil: %v", wafPolicy2.ruleEngine == nil)
		} else {
			t.Logf("✓ Cached config correctly blocks SQL injection")
		}
	})
}

