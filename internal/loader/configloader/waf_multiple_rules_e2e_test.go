package configloader

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestWAFMultipleRules_SQLInjection tests WAF multiple rules config with SQL injection
// This test reproduces the E2E issue where SQL injection is not being blocked
func TestWAFMultipleRules_SQLInjection(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the upstream
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer mockUpstream.Close()

	// Load the WAF multiple rules config (from 61-waf-multiple-rules.json)
	configJSON := `{
	  "id": "waf-multiple",
	  "hostname": "waf-multiple.test",
			"workspace_id": "test-workspace",
	  "action": {
	    "type": "proxy",
	    "url": "` + mockUpstream.URL + `"
	  },
	  "policies": [
	    {
	      "type": "waf",
	      "disabled": false,
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
	        },
	        {
	          "id": "block-xss",
	          "name": "Block XSS",
	          "disabled": false,
	          "phase": 2,
	          "severity": "high",
	          "action": "block",
	          "variables": [
	            {
	              "name": "ARGS",
	              "collection": "ARGS"
	            }
	          ],
	          "operator": "rx",
	          "pattern": "(?i)(<script|javascript:|onerror=)",
	          "transformations": ["lowercase", "urlDecode"]
	        },
	        {
	          "id": "block-path-traversal",
	          "name": "Block Path Traversal",
	          "disabled": false,
	          "phase": 2,
	          "severity": "high",
	          "action": "block",
	          "variables": [
	            {
	              "name": "REQUEST_URI",
	              "collection": "REQUEST_URI"
	            }
	          ],
	          "operator": "rx",
	          "pattern": "(?i)(\\.\\./|\\.\\.\\\\\\\\)",
	          "transformations": ["urlDecode"]
	        }
	      ],
	      "default_action": "log",
	      "action_on_match": "block"
	    }
	  ]
	}`

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"waf-multiple.test": []byte(configJSON),
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

	t.Run("SQL injection in query parameter should be blocked (403)", func(t *testing.T) {
		// Make a request with SQL injection payload (URL encoded)
		req := httptest.NewRequest("GET", "http://waf-multiple.test/?id=1%27+OR+%271%27%3D%271", nil)
		req.Host = "waf-multiple.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Create a response recorder
		w := httptest.NewRecorder()

		// Execute the request
		cfg.ServeHTTP(w, req)

		// Check response - should be 403, not 200
		if w.Code == 200 {
			t.Errorf("Got 200 OK - WAF should block SQL injection. Expected 403, got %d", w.Code)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d. Body: %s", w.Code, w.Body.String())
		}

		t.Logf("SQL injection request status: %d", w.Code)
		t.Logf("Response body: %s", w.Body.String())
	})

	t.Run("Path traversal in URL should be blocked (403)", func(t *testing.T) {
		// Make a request with path traversal payload
		req := httptest.NewRequest("GET", "http://waf-multiple.test/../../../etc/passwd", nil)
		req.Host = "waf-multiple.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Create a response recorder
		w := httptest.NewRecorder()

		// Execute the request
		cfg.ServeHTTP(w, req)

		// Check response - should be 403, not 200
		if w.Code == 200 {
			t.Errorf("Got 200 OK - WAF should block path traversal. Expected 403, got %d", w.Code)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d. Body: %s", w.Code, w.Body.String())
		}

		t.Logf("Path traversal request status: %d", w.Code)
		t.Logf("Response body: %s", w.Body.String())
	})

	t.Run("Normal request without attack should be allowed (200)", func(t *testing.T) {
		// Make a normal request without attack payload
		req := httptest.NewRequest("GET", "http://waf-multiple.test/?id=123", nil)
		req.Host = "waf-multiple.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Create a response recorder
		w := httptest.NewRecorder()

		// Execute the request
		cfg.ServeHTTP(w, req)

		// Check response - should be 200 for normal requests
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for normal request, got %d. Body: %s", w.Code, w.Body.String())
		}

		t.Logf("Normal request status: %d", w.Code)
	})
}

