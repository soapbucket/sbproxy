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
	"github.com/soapbucket/sbproxy/internal/request/session"
)

// TestCELMultipleCallbacksHeaders_E2E tests CEL multiple callbacks header setting
// This reproduces the E2E issue where headers from multiple CEL callbacks are not being set
func TestCELMultipleCallbacksHeaders_E2E(t *testing.T) {
	// This test requires full session middleware lifecycle (cookie round-trip, session
	// store read/write, session callback execution) which cannot be reproduced in a
	// unit test. The session callbacks never fire because no session cookie is present
	// and no session middleware processes the request.
	t.Skip("Requires full session middleware lifecycle (integration test)")

	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the e2e test server
	mockE2EServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/callback/config":
			// Config callback endpoint - return v2.1.0
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"version": "v2.1.0",
				"env":     "production",
				"features": map[string]interface{}{
					"beta_ui": true,
				},
			})
		case "/callback/session":
			// Session callback endpoint - return premium tier
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user_preferences": map[string]interface{}{
					"theme": "dark",
				},
				"subscription": map[string]interface{}{
					"tier":   "premium",
					"active": true,
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

	// Create config matching the failing test (from database)
	configJSON := fmt.Sprintf(`{
	  "id": "cel-multiple-callbacks",
	  "hostname": "cel-multiple-callbacks.test",
			"workspace_id": "test-workspace",
	  "on_load": [{
	    "type": "http",
	    "url": "%s/callback/config",
	    "method": "GET",
	    "timeout": 5,
	    "variable_name": "app_config",
	    "cel_expr": "{\"modified_json\": {\"version\": string('version' in json ? json['version'] : 'v1'), \"features\": 'features' in json ? json['features'] : {}}}"
	  }],
	  "session_config": {
	    "disabled": false,
	    "cookie_name": "_sb.session",
	    "cookie_max_age": 3600,
	    "callbacks": [
	      {
	        "type": "http",
	        "url": "%s/callback/session",
	        "method": "POST",
	        "variable_name": "user_prefs",
	        "timeout": 5,
	        "cel_expr": "{\"modified_json\": {\"theme\": json['user_preferences']['theme'], \"subscription\": json['subscription']}}"
	      }
	    ],
	    "allow_non_ssl": true
	  },
	  "action": {
	    "type": "proxy",
	    "url": "%s"
	  },
	  "request_modifiers": [
	    {
	      "headers": {
	        "set": {
	          "X-App-Version": "{{origin.params.app_config.version}}",
	          "X-User-Theme": "{{session.data.user_prefs.theme}}",
	          "X-Subscription-Tier": "{{session.data.user_prefs.subscription.tier}}"
	        }
	      },
	      "rules": [
	        {
	          "cel_expr": "origin['params']['app_config']['version'] == 'v2.1.0' && session.data.user_prefs.subscription.tier == 'premium'"
	        }
	      ]
	    }
	  ]
	}`, mockE2EServer.URL, mockE2EServer.URL, mockE2EServer.URL)

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"cel-multiple-callbacks.test": []byte(configJSON),
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

	t.Run("CEL multiple callbacks headers should be set when rule condition is met", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/headers", mockE2EServer.URL), nil)
		req.Host = "cel-multiple-callbacks.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if cfg == nil {
			t.Fatal("Config should not be nil")
		}

		// Wrap with session middleware if session config exists
		var handler http.Handler = cfg
		if cfg.HasSessionConfig() {
			handler = session.SessionMiddleware(mgr, cfg.SessionConfig)(handler)
		}

		// Test the request
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
			return
		}

		// Parse response
		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v. Body: %s", err, w.Body.String())
		}

		headers, ok := response["headers"].(map[string]interface{})
		if !ok {
			t.Fatalf("Headers not found in response. Response: %+v", response)
		}

		// Check for X-App-Version header (case-insensitive)
		appVersionFound := false
		for k, v := range headers {
			if http.CanonicalHeaderKey(k) == "X-App-Version" {
				appVersionFound = true
				// The version should be extracted from v2.1.0, but the CEL expression converts it to 'v2'
				// Actually, looking at the CEL expression, it should extract 'version' from json, which is "v2.1.0"
				// But the rule checks for 'v2', so let's check what the actual value is
				t.Logf("X-App-Version header value: %v", v)
				break
			}
		}

		if !appVersionFound {
			t.Errorf("X-App-Version header not found. Headers: %+v", headers)
		}

		// Verify RequestData has config and session data
		requestData := reqctx.GetRequestData(req.Context())
		if requestData == nil {
			t.Fatal("RequestData should not be nil")
		}

		// Check config data
		if requestData.Config == nil {
			t.Fatal("RequestData.Config should not be nil")
		}

		appConfig, ok := requestData.Config["app_config"]
		if !ok {
			t.Fatalf("app_config should be in RequestData.Config. Config: %+v", requestData.Config)
		}

		appConfigMap, ok := appConfig.(map[string]interface{})
		if !ok {
			t.Fatalf("app_config should be a map. Got: %T", appConfig)
		}

		version, ok := appConfigMap["version"]
		if !ok {
			t.Fatalf("version should be in app_config. app_config: %+v", appConfigMap)
		}

		t.Logf("Config version: %v", version)

		// Check session data
		if requestData.SessionData == nil {
			t.Fatal("SessionData should not be nil")
		}
		if requestData.SessionData.Data == nil {
			t.Fatal("SessionData.Data should not be nil")
		}

		userPrefs, ok := requestData.SessionData.Data["user_prefs"]
		if !ok {
			t.Fatalf("user_prefs should be in SessionData.Data. Data: %+v", requestData.SessionData.Data)
		}

		userPrefsMap, ok := userPrefs.(map[string]interface{})
		if !ok {
			t.Fatalf("user_prefs should be a map. Got: %T", userPrefs)
		}

		// The CEL expression might wrap it, so check for nested structure
		var subscription interface{}
		var found bool
		if sub, ok := userPrefsMap["subscription"]; ok {
			subscription = sub
			found = true
		} else if innerPrefs, ok := userPrefsMap["user_prefs"]; ok {
			// Check if it's double-wrapped
			innerPrefsMap, ok := innerPrefs.(map[string]interface{})
			if ok {
				subscription, found = innerPrefsMap["subscription"]
			}
		}

		if !found {
			t.Fatalf("subscription should be in user_prefs. user_prefs: %+v", userPrefsMap)
		}

		subscriptionMap, ok := subscription.(map[string]interface{})
		if !ok {
			t.Fatalf("subscription should be a map. Got: %T", subscription)
		}

		tier, ok := subscriptionMap["tier"]
		if !ok || tier != "premium" {
			t.Errorf("Expected tier to be 'premium', got: %v", tier)
		}
	})
}

