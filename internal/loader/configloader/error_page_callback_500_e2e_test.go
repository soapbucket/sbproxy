package configloader

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestErrorPageCallback500_E2E tests the exact failing scenario from E2E tests
// This test uses the exact configuration from the database that failed
// Expected: 500 error should trigger callback and return 500 with custom error page
// Actual: Returns 200 (not intercepting the error)
func TestErrorPageCallback500_E2E(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server that returns 500 error
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test/error-500" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	// Create a mock server for the error callback
	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error/500" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body><h1>Error page fetched from callback</h1></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockCallbackServer.Close()

	// Exact config from database (failing config)
	configJSON := `{
		"id": "error-pages-callbacks",
		"hostname": "error-pages-callbacks.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "` + mockUpstream.URL + `"
		},
		"error_pages": [
			{
				"status": [500],
				"callback": {
					"type": "http",
					"url": "` + mockCallbackServer.URL + `/error/500",
					"method": "GET",
					"cache_duration": "10m"
				},
				"content_type": "text/html"
			}
		]
	}`

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"error-pages-callbacks.test": []byte(configJSON),
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

	t.Run("500 error should trigger callback and return 500 status", func(t *testing.T) {
		// This is the exact test case that failed in E2E
		// URL: http://localhost:8080/test/error-500
		// Host: error-pages-callbacks.test
		// Expected: 500 with custom error page from callback
		// Actual: 200

		req := httptest.NewRequest("GET", "http://error-pages-callbacks.test/test/error-500", nil)
		req.Host = "error-pages-callbacks.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Create a response recorder
		w := httptest.NewRecorder()

		// Execute the request through the full handler chain
		cfg.ServeHTTP(w, req)

		// Check response
		t.Logf("Response Status: %d", w.Code)
		t.Logf("Response Headers: %v", w.Header())
		t.Logf("Response Body: %s", w.Body.String())

		if w.Code == http.StatusOK {
			t.Errorf("FAIL: 500 error was not intercepted. Expected 500, got %d", w.Code)
			t.Logf("\n=== DIAGNOSIS ===")
			t.Logf("The error page callback is not being triggered for 500 errors.")
			t.Logf("Possible causes:")
			t.Logf("  1. replaceResponseWithErrorPage() not handling callbacks")
			t.Logf("  2. Error page callback not being fetched")
			t.Logf("  3. Status code not being preserved (returning 200 instead of 500)")
			t.Logf("  4. Error page not matching 500 status code")
		} else if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500 Internal Server Error, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			// Check if the body contains the callback content
			body := w.Body.String()
			if !strings.Contains(body, "Error page fetched from callback") {
				t.Errorf("Expected error page content from callback, got: %s", body)
			} else {
				t.Logf("✓ PASS: 500 error correctly intercepted with callback content")
			}
		}
	})

	t.Run("Normal request should return 200", func(t *testing.T) {
		// Verify normal requests still work
		req := httptest.NewRequest("GET", "http://error-pages-callbacks.test/test/simple-200", nil)
		req.Host = "error-pages-callbacks.test"

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
