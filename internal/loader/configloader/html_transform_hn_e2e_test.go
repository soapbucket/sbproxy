package configloader

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestHTMLTransformHN_405Error tests the HTML transform HN config that's getting 405 errors
// This test reproduces the E2E issue where HEAD requests return 405
func TestHTMLTransformHN_405Error(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the upstream
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate YCombinator response
		if r.Method == "HEAD" {
			// Some servers don't support HEAD, but we'll simulate it does
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Test Page</title></head><body>Test Content</body></html>`))
	}))
	defer mockUpstream.Close()

	// Update config to use mock server
	configJSONWithMock := `{
	  "id": "html-transform-hn",
	  "hostname": "html-transform-hn.test",
			"workspace_id": "test-workspace",
	  "action": {
	    "type": "proxy",
	    "url": "` + mockUpstream.URL + `",
	    "skip_tls_verify_host": true
	  },
	  "transforms": [
	    {
	      "type": "optimized_html",
	      "content_types": ["text/html"],
	      "optimized_format_options": {
	        "strip_comments": true,
	        "remove_trailing_slashes": true,
	        "optimize_attributes": true,
	        "minify_css": true,
	        "minify_javascript": true
	      },
	      "add_to_tags": [
	        {
	          "tag": "head",
	          "add_before_end_tag": false,
	          "content": "<meta name=\"proxy\" content=\"soapbucket\">"
	        }
	      ],
	      "modify_tags": [
	        {
	          "selector": "title",
	          "action": "prepend",
	          "content": "[Proxied] "
	        }
	      ]
	    }
	  ]
	}`

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"html-transform-hn.test": []byte(configJSONWithMock),
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

	t.Run("HEAD request should return 200, not 405", func(t *testing.T) {
		// Make a HEAD request (like the E2E test does)
		req := httptest.NewRequest("HEAD", "http://html-transform-hn.test/", nil)
		req.Host = "html-transform-hn.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Create a response recorder
		w := httptest.NewRecorder()

		// Execute the request
		cfg.ServeHTTP(w, req)

		// Check response - should be 200, not 405
		if w.Code == 405 {
			t.Errorf("Got 405 Method Not Allowed - HTML transform may not be handling HEAD requests correctly")
		}
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		t.Logf("HEAD request status: %d", w.Code)
	})

	t.Run("OPTIONS request should return 200, not 405", func(t *testing.T) {
		// Make an OPTIONS request (CORS preflight)
		req := httptest.NewRequest("OPTIONS", "http://html-transform-hn.test/", nil)
		req.Host = "html-transform-hn.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Create a response recorder
		w := httptest.NewRecorder()

		// Execute the request
		cfg.ServeHTTP(w, req)

		// Check response - should be 204 (No Content) or 200, not 405
		// 204 is the correct HTTP status for OPTIONS requests
		if w.Code == 405 {
			t.Errorf("Got 405 Method Not Allowed - HTML transform may not be handling OPTIONS requests correctly")
		}
		if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
			t.Errorf("Expected 204 or 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		t.Logf("OPTIONS request status: %d", w.Code)
	})

	t.Run("GET request should work", func(t *testing.T) {
		// Make a GET request to verify the transform works
		req := httptest.NewRequest("GET", "http://html-transform-hn.test/", nil)
		req.Host = "html-transform-hn.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Create a response recorder
		w := httptest.NewRecorder()

		// Execute the request
		cfg.ServeHTTP(w, req)

		// Check response
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		// Check if transform was applied (should have meta tag)
		body := w.Body.String()
		if !strings.Contains(body, "soapbucket") {
			t.Logf("Transform may not have been applied. Body: %s", body)
		}

		t.Logf("GET request status: %d", w.Code)
		t.Logf("Response body length: %d", len(body))
	})
}

