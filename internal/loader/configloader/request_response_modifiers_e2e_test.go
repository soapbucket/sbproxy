package configloader

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestRequestModifiersHeader_TemplateVariables tests request modifiers with template variables
// This test reproduces the E2E issue where headers with template variables aren't being set
func TestRequestModifiersHeader_TemplateVariables(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server that echoes request headers
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo request headers in response body for testing
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		// Return headers as JSON so we can verify they were set
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		
		// Simple JSON response with headers
		response := `{"headers":{`
		first := true
		for k, v := range headers {
			if !first {
				response += ","
			}
			response += `"` + k + `":"` + v + `"`
			first = false
		}
		response += `}}`
		w.Write([]byte(response))
	}))
	defer mockUpstream.Close()

	// Load the request modifiers config (from 71-request-modifiers-complex.json)
	configJSON := `{
	  "id": "request-modifiers-complex",
	  "hostname": "request-modifiers-complex.test",
			"workspace_id": "test-workspace",
	  "action": {
	    "type": "proxy",
	    "url": "` + mockUpstream.URL + `"
	  },
	  "request_modifiers": [
	    {
	      "headers": {
	        "set": {
	          "X-Forwarded-Proto": "https",
	          "X-Real-IP": "{{request.remote_addr}}",
	          "X-Request-ID": "{{request.id}}"
	        },
	        "remove": ["X-Forwarded-For"]
	      }
	    }
	  ]
	}`

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"request-modifiers-complex.test": []byte(configJSON),
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

	t.Run("Request modifier headers with template variables should be set", func(t *testing.T) {
		// Make a request
		req := httptest.NewRequest("GET", "http://request-modifiers-complex.test/api/headers", nil)
		req.Host = "request-modifiers-complex.test"
		req.RemoteAddr = "192.168.1.100:12345"

		// Create RequestData with ID (simulating RequestDataMiddleware)
		requestData := reqctx.NewRequestData()
		requestData.ID = "test-request-id-123"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

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

		// Check if headers were set (should be in response body from upstream)
		body := w.Body.String()
		// Headers are case-insensitive, but JSON keys are case-sensitive
		// The upstream server returns headers in the response body as JSON
		// Check for the actual JSON keys (which may be normalized by the server)
		if !strings.Contains(body, "X-Request-Id") && !strings.Contains(body, "X-Request-ID") {
			t.Errorf("Expected X-Request-ID header to be set. Response body: %s", body)
		}

		// Check if X-Real-IP header was set with remote address
		if !strings.Contains(body, "X-Real-Ip") && !strings.Contains(body, "X-Real-IP") {
			t.Errorf("Expected X-Real-IP header to be set. Response body: %s", body)
		}

		// Check if X-Forwarded-Proto header was set
		if !strings.Contains(body, "X-Forwarded-Proto") {
			t.Errorf("Expected X-Forwarded-Proto header to be set. Response body: %s", body)
		}

		// Verify the actual values are set (not empty)
		if !strings.Contains(body, `"X-Request-Id":"test-request-id-123"`) && !strings.Contains(body, `"X-Request-ID":"test-request-id-123"`) {
			t.Errorf("Expected X-Request-ID to have value 'test-request-id-123'. Response body: %s", body)
		}

		if !strings.Contains(body, `"X-Real-Ip":"192.168.1.100"`) && !strings.Contains(body, `"X-Real-IP":"192.168.1.100"`) {
			t.Errorf("Expected X-Real-IP to have value '192.168.1.100'. Response body: %s", body)
		}

		t.Logf("Response status: %d", w.Code)
		t.Logf("Response body: %s", body)
	})
}

// TestResponseModifiersHeader tests response modifiers with headers
// This test reproduces the E2E issue where response headers aren't being set
func TestResponseModifiersHeader(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	// Load the response modifiers config (from 72-response-modifiers-complex.json)
	configJSON := `{
	  "id": "response-modifiers-complex",
	  "hostname": "response-modifiers-complex.test",
			"workspace_id": "test-workspace",
	  "action": {
	    "type": "proxy",
	    "url": "` + mockUpstream.URL + `"
	  },
	  "response_modifiers": [
	    {
	      "headers": {
	        "set": {
	          "X-Proxy-Version": "1.0.0",
	          "X-Processed-By": "soapbucket"
	        },
	        "remove": ["X-Powered-By"]
	      }
	    }
	  ]
	}`

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"response-modifiers-complex.test": []byte(configJSON),
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

	t.Run("Response modifier headers should be set", func(t *testing.T) {
		// Make a request
		req := httptest.NewRequest("GET", "http://response-modifiers-complex.test/api/headers", nil)
		req.Host = "response-modifiers-complex.test"

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

		// Check if X-Proxy-Version header was set in response
		if w.Header().Get("X-Proxy-Version") != "1.0.0" {
			t.Errorf("Expected X-Proxy-Version header to be '1.0.0', got '%s'", w.Header().Get("X-Proxy-Version"))
		}

		// Check if X-Processed-By header was set
		if w.Header().Get("X-Processed-By") != "soapbucket" {
			t.Errorf("Expected X-Processed-By header to be 'soapbucket', got '%s'", w.Header().Get("X-Processed-By"))
		}

		t.Logf("Response status: %d", w.Code)
		t.Logf("Response headers: %v", w.Header())
	})
}

