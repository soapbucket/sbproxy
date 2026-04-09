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

// TestCELExpressionPolicyCallback tests the CEL expression policy with on_load callback
// This reproduces the E2E issue where the policy blocks requests even when enabled is true
func TestCELExpressionPolicyCallback(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the callback endpoint
	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/callback/config" {
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
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer mockCallbackServer.Close()

	// Create config matching the failing test
	configJSON := fmt.Sprintf(`{
	  "id": "cel-expression-policy-callback",
	  "hostname": "cel-expression-policy-callback.test",
			"workspace_id": "test-workspace",
	  "on_load": [{
	    "type": "http",
	    "url": "%s/callback/config",
	    "method": "GET",
	    "timeout": 5,
	    "variable_name": "app_config"
	  }],
	  "action": {
	    "type": "proxy",
	    "url": "%s"
	  },
	  "policies": [
	    {
	      "type": "expression",
	      "disabled": false,
	      "cel_expr": "origin.params.app_config.enabled == true && request.method == 'GET'"
	    }
	  ]
	}`, mockCallbackServer.URL, mockCallbackServer.URL)

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"cel-expression-policy-callback.test": []byte(configJSON),
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

	t.Run("CEL expression policy should allow GET request when enabled is true", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://cel-expression-policy-callback.test/", nil)
		req.Host = "cel-expression-policy-callback.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Verify config was loaded and on_load callback executed
		if cfg == nil {
			t.Fatal("Config should not be nil")
		}

		// Check if Params contains app_config
		if cfg.Params == nil {
			t.Fatal("Params should not be nil after on_load callback")
		}

		appConfig, ok := cfg.Params["app_config"]
		if !ok {
			t.Fatalf("app_config should be in Params. Params: %+v", cfg.Params)
		}

		appConfigMap, ok := appConfig.(map[string]any)
		if !ok {
			t.Fatalf("app_config should be a map. Got: %T", appConfig)
		}

		enabled, ok := appConfigMap["enabled"]
		if !ok {
			t.Fatalf("enabled should be in app_config. app_config: %+v", appConfigMap)
		}

		if enabled != true {
			t.Errorf("enabled should be true, got: %v", enabled)
		}

		// Verify RequestData.Config is populated
		requestData := reqctx.GetRequestData(req.Context())
		if requestData == nil {
			t.Fatal("RequestData should not be nil")
		}
		if requestData.Config == nil {
			t.Fatal("RequestData.Config should not be nil")
		}
		appConfigFromRequestData, ok := requestData.Config["app_config"]
		if !ok {
			t.Fatalf("app_config should be in RequestData.Config. Config: %+v", requestData.Config)
		}
		t.Logf("RequestData.Config: %+v", requestData.Config)
		t.Logf("app_config from RequestData.Config: %+v", appConfigFromRequestData)

		// Test the request
		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
}

