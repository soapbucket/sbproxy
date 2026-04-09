package configloader

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestWAFXSSFailure_E2E tests the exact failing scenario from E2E tests
// This test uses the exact configuration from the database that failed
// Expected: XSS attempt should be blocked with 403
// Actual: Returns 200 (not blocked)
func TestWAFXSSFailure_E2E(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the upstream
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer mockUpstream.Close()

	// Config with XSS rule added (fixed config)
	// This config now includes both SQL injection and XSS rules
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
						"pattern": "(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|update\\s+.*\\s+set|delete\\s+from|drop\\s+table|truncate\\s+table|alter\\s+table|exec\\s*\\(|execute\\s*\\(|sp_executesql|\\bor\\s+['\"]?1\\s*=\\s*['\"]?1|\\band\\s+['\"]?1\\s*=\\s*['\"]?1|'or'1'='1|'and'1'='1|'\\s*or\\s*'1'\\s*=\\s*'1|'\\s*and\\s*'1'\\s*=\\s*'1)",
						"transformations": ["lowercase", "urlDecode"]
					},
					{
						"id": "block-xss",
						"name": "Block XSS Attempts",
						"disabled": false,
						"phase": 2,
						"severity": "critical",
						"action": "block",
						"variables": [
							{
								"name": "ARGS",
								"collection": "ARGS"
							},
							{
								"name": "REQUEST_URI",
								"collection": "REQUEST_URI"
							}
						],
						"operator": "rx",
						"pattern": "(?i)(<script[^>]*>|</script>|javascript\\s*:|on\\w+\\s*=|<iframe[^>]*>|<img[^>]*onerror)",
						"transformations": ["lowercase", "htmlEntityDecode", "urlDecode"]
					}
				],
				"default_action": "log",
				"action_on_match": "block"
			}
		],
		"action": {
			"type": "proxy",
			"url": "` + mockUpstream.URL + `"
		}
	}`

	// Create mock storage with config
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

	t.Run("XSS attempt should be blocked (403) - exact E2E failure case", func(t *testing.T) {
		// This is the exact test case that failed in E2E
		// URL: http://localhost:8080/?q=<script>alert(1)</script>
		// Host: waf.test
		// Expected: 403
		// Actual: 200

		req := httptest.NewRequest("GET", "http://waf.test/?q=<script>alert(1)</script>", nil)
		req.Host = "waf.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Create a response recorder
		w := httptest.NewRecorder()

		// Execute the request through the full handler chain
		cfg.ServeHTTP(w, req)

		// Check response - should be 403, not 200
		t.Logf("Response Status: %d", w.Code)
		t.Logf("Response Headers: %v", w.Header())
		t.Logf("Response Body: %s", w.Body.String())

		if w.Code == http.StatusOK {
			t.Errorf("FAIL: XSS attempt was not blocked. Expected 403, got %d", w.Code)
			t.Logf("\n=== DIAGNOSIS ===")
			t.Logf("The WAF policy is not blocking the XSS attempt.")
			t.Logf("Possible causes:")
			t.Logf("  1. No XSS rule configured in WAF policy")
			t.Logf("  2. WAF rule engine not evaluating XSS patterns")
			t.Logf("  3. Pattern matching not working for <script> tags")
			t.Logf("  4. URL encoding not being handled correctly")
			t.Logf("  5. WAF Apply() method not being called in handler chain")
		} else if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ PASS: XSS attempt correctly blocked with 403")
		}
	})

	t.Run("SQL injection should still be blocked (403)", func(t *testing.T) {
		// Verify SQL injection still works (baseline test)
		req := httptest.NewRequest("GET", "http://waf.test/?id=1%27+OR+%271%27%3D%271", nil)
		req.Host = "waf.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("SQL injection should be blocked. Expected 403, got %d", w.Code)
		} else {
			t.Logf("✓ SQL injection correctly blocked")
		}
	})

	t.Run("Normal request should be allowed (200)", func(t *testing.T) {
		// Verify normal requests still work
		req := httptest.NewRequest("GET", "http://waf.test/?q=normal+query", nil)
		req.Host = "waf.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Normal request should be allowed. Expected 200, got %d", w.Code)
		} else {
			t.Logf("✓ Normal request correctly allowed")
		}
	})
}
