package configloader

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestWAFConfigFromStorage tests loading WAF config from storage and verifying it blocks requests
func TestWAFConfigFromStorage(t *testing.T) {
	// Reset cache
	resetCache()

	// WAF config JSON (exact format from database)
	wafJSON := `{
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

	// Create mock storage
	mockStore := &mockStorage{
		data: map[string][]byte{
			"waf.test": []byte(wafJSON),
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

	// Load config (simulates configloader.Load)
	req := httptest.NewRequest("GET", "http://waf.test/?id=1%27%20OR%20%271", nil)
	req.Host = "waf.test"

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	t.Logf("✓ Config loaded from storage")
	t.Logf("  - Config ID: %s", cfg.ID)
	t.Logf("  - Config Hostname: %s", cfg.Hostname)

	// Test WAF blocking through full Config.ServeHTTP (like E2E test)
	t.Run("WAF blocks SQL injection via ServeHTTP", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=1%27%20OR%20%271")
		req := httptest.NewRequest("GET", reqURL.String(), nil)
		req.Host = "waf.test"
		w := httptest.NewRecorder()

		// Use Config.ServeHTTP which applies all middleware
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ WAF correctly blocks SQL injection via ServeHTTP")
		}
	})

	// Test normal request passes through
	t.Run("Normal request allowed via ServeHTTP", func(t *testing.T) {
		reqURL, _ := url.Parse("http://waf.test/?id=123")
		req := httptest.NewRequest("GET", reqURL.String(), nil)
		req.Host = "waf.test"
		w := httptest.NewRecorder()

		cfg.ServeHTTP(w, req)

		// Should get error from proxy (since e2e-test-server isn't running in test)
		// But should NOT be 403 (blocked by WAF)
		if w.Code == http.StatusForbidden {
			t.Error("Normal request should not be blocked by WAF")
		}
	})

	// Test cached config
	t.Run("WAF works with cached config", func(t *testing.T) {
		// Load again - should come from cache
		req2 := httptest.NewRequest("GET", "http://waf.test/?id=1%27%20OR%20%271", nil)
		req2.Host = "waf.test"

		cfg2, err := Load(req2, mgr)
		if err != nil {
			t.Fatalf("Failed to load cached config: %v", err)
		}

		// Test blocking with cached config
		reqURL, _ := url.Parse("http://waf.test/?id=1%27%20OR%20%271")
		req := httptest.NewRequest("GET", reqURL.String(), nil)
		req.Host = "waf.test"
		w := httptest.NewRecorder()

		cfg2.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403 with cached config, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ Cached config correctly blocks SQL injection")
		}
	})
}

