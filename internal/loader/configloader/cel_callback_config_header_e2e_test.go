package configloader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestCELCallbackConfigHeader_E2E tests the exact failing config from fixtures
// This reproduces the E2E issue where X-API-Version header is not being set
func TestCELCallbackConfigHeader_E2E(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the e2e test server
	mockE2EServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/callback/config":
			// Config callback endpoint - matches e2e-test-server response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"version": "v2.1.0",
				"env":     "production",
				"enabled": true,
				"features": map[string]interface{}{
					"beta_ui":      true,
					"api_v2":       true,
					"websockets":   true,
					"file_uploads": true,
				},
				"limits": map[string]interface{}{
					"max_upload_size": 10485760,
					"max_connections": 1000,
				},
			})
		case "/api/headers":
			// Echo headers endpoint
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			headers := make(map[string]string)
			for k, v := range r.Header {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"count":   len(headers),
				"headers": headers,
			})
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer mockE2EServer.Close()

	// Use the exact config from fixtures/73-cel-callback-onload.json
	configJSON := fmt.Sprintf(`{
	  "id": "cel-callback-onload",
	  "hostname": "cel-callback-onload.test",
			"workspace_id": "test-workspace",
	  "on_load": [{
	    "type": "http",
	    "url": "%s/callback/config",
	    "method": "GET",
	    "timeout": 5,
	    "cel_expr": "{\"modified_json\": {\"config_data\": {\"api_version\": string('version' in json ? json['version'] : 'v1'), \"environment\": 'env' in json ? json['env'] : 'production', \"features\": 'features' in json ? json['features'] : {}}}}"
	  }],
	  "action": {
	    "type": "proxy",
	    "url": "%s"
	  },
	  "request_modifiers": [
	    {
	      "headers": {
	        "set": {
	          "X-API-Version": "{{origin.params.config_data.api_version}}",
	          "X-Environment": "{{origin.params.config_data.environment}}"
	        }
	      }
	    }
	  ]
	}`, mockE2EServer.URL, mockE2EServer.URL)

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"cel-callback-onload.test": []byte(configJSON),
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

	t.Run("CEL callback should set X-API-Version header from config_data", func(t *testing.T) {
		// Create request
		req := httptest.NewRequest(http.MethodGet, "http://cel-callback-onload.test/api/headers", nil)
		req.Host = "cel-callback-onload.test"

		// Load config
		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Debug: Check what's in Config.Params
		if cfg != nil && cfg.Params != nil {
			t.Logf("Config.Params length: %d, keys: %v", len(cfg.Params), getMapKeys(cfg.Params))
			if configData, ok := cfg.Params["config_data"]; ok {
				t.Logf("Config.Params['config_data'] type: %T", configData)
				if configDataMap, ok := configData.(map[string]interface{}); ok {
					t.Logf("Config.Params['config_data'] keys: %v", getMapKeysFromInterfaceMap(configDataMap))
					if apiVersion, ok := configDataMap["api_version"]; ok {
						t.Logf("Config.Params['config_data']['api_version']: %v (type: %T)", apiVersion, apiVersion)
					}
				}
			}
		}

		// Debug: Check what's in RequestData.Config after Load
		requestData := reqctx.GetRequestData(req.Context())
		if requestData == nil {
			t.Fatal("RequestData should not be nil after Load")
		}
		if requestData.Config == nil {
			t.Fatal("RequestData.Config should not be nil after Load")
		}
		t.Logf("RequestData.Config length: %d, keys: %v", len(requestData.Config), getMapKeys(requestData.Config))
		if configData, ok := requestData.Config["config_data"]; ok {
			t.Logf("RequestData.Config['config_data'] type: %T", configData)
			if configDataMap, ok := configData.(map[string]interface{}); ok {
				t.Logf("RequestData.Config['config_data'] keys: %v", getMapKeysFromInterfaceMap(configDataMap))
				if apiVersion, ok := configDataMap["api_version"]; ok {
					t.Logf("RequestData.Config['config_data']['api_version']: %v (type: %T)", apiVersion, apiVersion)
				}
			} else if configDataMap, ok := configData.(map[string]any); ok {
				t.Logf("RequestData.Config['config_data'] keys (map[string]any): %v", getMapKeys(configDataMap))
				if apiVersion, ok := configDataMap["api_version"]; ok {
					t.Logf("RequestData.Config['config_data']['api_version']: %v (type: %T)", apiVersion, apiVersion)
				}
			}
		}

		// Execute request
		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		// Check response
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
			return
		}

		// Parse response JSON to check headers
		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response JSON: %v. Body: %s", err, w.Body.String())
		}

		headers, ok := response["headers"].(map[string]interface{})
		if !ok {
			t.Fatalf("Response should contain headers map. Response: %+v", response)
		}

		// Check for expected header (case-insensitive)
		found := false
		var actualValue string
		for k, v := range headers {
			if k == "X-API-Version" || 
			   (len(k) == len("X-API-Version") && 
			    equalsIgnoreCase(k, "X-API-Version")) {
				found = true
				if str, ok := v.(string); ok {
					actualValue = str
				} else {
					actualValue = fmt.Sprintf("%v", v)
				}
				break
			}
		}

		if !found {
			t.Errorf("Expected header X-API-Version not found. Headers: %+v", headers)
			return
		}

		if actualValue == "" {
			t.Errorf("X-API-Version header is empty. This means template variable {{origin.params.config_data.api_version}} is not resolving. Headers: %+v", headers)
			
			// Debug: Try to manually resolve the template variable
			requestData = reqctx.GetRequestData(req.Context())
			if requestData != nil && requestData.Config != nil {
				t.Logf("Debug: RequestData.Config at time of header resolution: %+v", requestData.Config)
				if configData, ok := requestData.Config["config_data"]; ok {
					t.Logf("Debug: config_data value: %+v (type: %T)", configData, configData)
				}
			}
			return
		}

		expectedValue := "v2.1.0"
		if actualValue != expectedValue {
			t.Errorf("Expected header X-API-Version to be %q, got %q", expectedValue, actualValue)
		} else {
			t.Logf("✓ X-API-Version header correctly set to %q", actualValue)
		}
	})
}

// Helper function to get map keys from map[string]interface{}
func getMapKeysFromInterfaceMap(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

