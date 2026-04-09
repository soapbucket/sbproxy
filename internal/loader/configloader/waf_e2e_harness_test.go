package configloader

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestWAFE2EFullFlow tests WAF with the full E2E flow using existing mocks
func TestWAFE2EFullFlow(t *testing.T) {
	// Reset cache
	resetCache()

	// WAF config (exact from E2E test)
	wafJSON := []byte(`{
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
	}`)

	// Create mock storage
	mockStore := &mockStorage{
		data: map[string][]byte{
			"waf.test": wafJSON,
		},
	}

	// Create mock manager
	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Log("=== WAF E2E Full Flow Test ===")

	// Test 1: Load config
	t.Run("Load config from storage", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://waf.test/?id=123", nil)
		req.Host = "waf.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		t.Logf("✓ Config loaded")
		t.Logf("  Config ID: %s", cfg.ID)
		t.Logf("  Config Hostname: %s", cfg.Hostname)
	})

	// Test 2: SQL injection should be blocked
	t.Run("SQL injection blocked", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=1%27%20OR%20%271")
		req := httptest.NewRequest("GET", reqURL.String(), nil)
		req.Host = "waf.test"

		t.Logf("Request URL: %s", reqURL.String())
		t.Logf("Query String: %s", reqURL.RawQuery)
		t.Logf("Query Values: %v", reqURL.Query())

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		t.Logf("Response Status: %d", w.Code)
		t.Logf("Response Headers: %v", w.Header())
		t.Logf("Response Body (first 200 chars): %s", w.Body.String()[:min(200, w.Body.Len())])

		if w.Code != http.StatusForbidden {
			t.Errorf("FAIL: Expected 403, got %d", w.Code)
			t.Logf("\n=== DIAGNOSIS ===")
			t.Logf("The WAF policy is not blocking the request.")
			t.Logf("Possible causes:")
			t.Logf("  1. WAF Apply() method not being called")
			t.Logf("  2. Rule engine not initialized (ruleEngine is nil)")
			t.Logf("  3. Rule not matching the request")
			t.Logf("  4. Policy disabled")
			t.Logf("  5. Config not loaded correctly")
		} else {
			t.Logf("✓ PASS: SQL injection correctly blocked with 403")
		}
	})

	// Test 3: Normal request should pass
	t.Run("Normal request allowed", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=123")
		req := httptest.NewRequest("GET", reqURL.String(), nil)
		req.Host = "waf.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusForbidden {
			t.Error("Normal request should not be blocked by WAF")
		} else {
			t.Logf("✓ Normal request not blocked (status: %d)", w.Code)
		}
	})

	// Test 4: Cached config
	t.Run("Cached config works", func(t *testing.T) {
		initialCallCount := mockStore.callCount

		// Load twice
		req1 := httptest.NewRequest("GET", "http://waf.test/?id=1%27%20OR%20%271", nil)
		req1.Host = "waf.test"

		cfg1, err := Load(req1, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		req2 := httptest.NewRequest("GET", "http://waf.test/?id=1%27%20OR%20%271", nil)
		req2.Host = "waf.test"

		cfg2, err := Load(req2, mgr)
		if err != nil {
			t.Fatalf("Failed to load cached config: %v", err)
		}

		if mockStore.callCount > initialCallCount+1 {
			t.Log("Note: Config loaded from storage multiple times (cache may not be working)")
		} else {
			t.Logf("✓ Config loaded from cache")
		}

		// Test cached config still blocks
		w := httptest.NewRecorder()
		cfg2.ServeHTTP(w, req2)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected cached config to block with 403, got %d", w.Code)
		} else {
			t.Logf("✓ Cached config correctly blocks")
		}

		if cfg1 != cfg2 {
			t.Log("Note: Configs are different instances")
		}
	})

	// Test 5: Multiple SQL injection patterns
	t.Run("Multiple SQL injection patterns", func(t *testing.T) {
		patterns := []struct {
			name string
			url  string
		}{
			{"OR injection", "http://waf.test/?id=1%27%20OR%20%271%27%3D%271"},
			{"UNION injection", "http://waf.test/?id=1%20UNION%20SELECT"},
			{"DROP injection", "http://waf.test/?id=1%3B%20DROP%20TABLE"},
			{"Comment injection", "http://waf.test/?id=1%27%20AND%201%3D1--"},
		}

		for _, pattern := range patterns {
			reqURL, _ := url.Parse(pattern.url)
			req := httptest.NewRequest("GET", reqURL.String(), nil)
			req.Host = "waf.test"

			cfg, err := Load(req, mgr)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			w := httptest.NewRecorder()
			cfg.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Pattern %q: Expected 403, got %d", pattern.name, w.Code)
			} else {
				t.Logf("✓ Pattern %q correctly blocked", pattern.name)
			}
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

