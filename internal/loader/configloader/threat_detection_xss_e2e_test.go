package configloader

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestThreatDetectionXSS_Blocking tests the threat detection XSS config that's not blocking XSS attempts
// This test reproduces the E2E issue where XSS payloads return 200 instead of 403
func TestThreatDetectionXSS_Blocking(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the upstream
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>OK</body></html>`))
	}))
	defer mockUpstream.Close()

	// Update config to use mock server
	configJSONWithMock := `{
	  "id": "threat-detection",
	  "hostname": "threat-detection.test",
			"workspace_id": "test-workspace",
	  "action": {
	    "type": "proxy",
	    "url": "` + mockUpstream.URL + `"
	  },
	  "policies": [
	    {
	      "type": "threat_detection",
	      "disabled": false,
	      "patterns": {
	        "xss": {
	          "disabled": false,
	          "action": "block",
	          "log_level": "warn"
	        },
	        "path_traversal": {
	          "disabled": false,
	          "action": "log",
	          "log_level": "info"
	        }
	      }
	    }
	  ]
	}`

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"threat-detection.test": []byte(configJSONWithMock),
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

	t.Run("XSS payload in query parameter should be blocked (403)", func(t *testing.T) {
		// Make a request with XSS payload in query parameter (like the E2E test)
		req := httptest.NewRequest("GET", "http://threat-detection.test/?q=<script>alert(1)</script>", nil)
		req.Host = "threat-detection.test"

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
			t.Errorf("Got 200 OK - Threat detection should block XSS payload. Expected 403, got %d", w.Code)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d. Body: %s", w.Code, w.Body.String())
		}

		t.Logf("XSS payload request status: %d", w.Code)
		t.Logf("Response body: %s", w.Body.String())
	})

	t.Run("Normal request without XSS should be allowed (200)", func(t *testing.T) {
		// Make a normal request without XSS payload
		req := httptest.NewRequest("GET", "http://threat-detection.test/?q=normal+query", nil)
		req.Host = "threat-detection.test"

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

	t.Run("XSS payload in different locations", func(t *testing.T) {
		testCases := []struct {
			name    string
			url     string
			headers map[string]string
			want    int
		}{
			{
				name: "XSS in query parameter",
				url:  "http://threat-detection.test/?q=<script>alert(1)</script>",
				want: http.StatusForbidden,
			},
			{
				name: "XSS in path",
				url:  "http://threat-detection.test/<script>alert(1)</script>",
				want: http.StatusForbidden,
			},
			{
				name: "XSS in header",
				url:  "http://threat-detection.test/",
				headers: map[string]string{
					"X-Custom-Header": "<script>alert(1)</script>",
				},
				want: http.StatusForbidden,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", tc.url, nil)
				req.Host = "threat-detection.test"
				for k, v := range tc.headers {
					req.Header.Set(k, v)
				}

				cfg, err := Load(req, mgr)
				if err != nil {
					t.Fatalf("Failed to load config: %v", err)
				}

				w := httptest.NewRecorder()
				cfg.ServeHTTP(w, req)

				if w.Code != tc.want {
					t.Errorf("Expected %d, got %d. Body: %s", tc.want, w.Code, w.Body.String())
				}
			})
		}
	})
}

