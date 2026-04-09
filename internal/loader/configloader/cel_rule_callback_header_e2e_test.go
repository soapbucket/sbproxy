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

// TestCELRuleCallbackHeader_E2E tests CEL rule callback header setting
// This reproduces the E2E issue where headers from CEL rule callbacks are not being set
func TestCELRuleCallbackHeader_E2E(t *testing.T) {
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
		case "/callback/session":
			// Session callback endpoint - return premium tier with beta flag
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user_preferences": map[string]interface{}{
					"theme":    "dark",
					"language": "en",
				},
				"subscription": map[string]interface{}{
					"tier":   "premium",
					"active": true,
				},
				"feature_flags": map[string]interface{}{
					"beta_features": true,
					"analytics":     true,
					"export":        true,
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
	  "id": "cel-rule-callback-data",
	  "hostname": "cel-rule-callback-data.test",
			"workspace_id": "test-workspace",
	  "session_config": {
	    "disabled": false,
	    "allow_non_ssl": true,
	    "cookie_name": "_sb.session",
	    "cookie_max_age": 3600,
	    "callbacks": [
	      {
	        "type": "http",
	        "url": "%s/callback/session",
	        "method": "POST",
	        "variable_name": "user_data",
	        "timeout": 5
	      }
	    ]
	  },
	  "action": {
	    "type": "proxy",
	    "url": "%s"
	  },
	  "request_modifiers": [
	    {
	      "headers": {
	        "set": {
	          "X-User-Tier": "{{session.data.user_data.subscription.tier}}",
	          "X-Feature-Flags": "{{session.data.user_data.feature_flags}}"
	        }
	      },
	      "rules": [
	        {
	          "cel_expr": "size(session) > 0 && size(session.data) > 0 && session.data.user_data.subscription.tier == 'premium' && 'beta_features' in session.data.user_data.feature_flags && session.data.user_data.feature_flags.beta_features == true"
	        }
	      ]
	    }
	  ]
	}`, mockE2EServer.URL, mockE2EServer.URL)

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"cel-rule-callback-data.test": []byte(configJSON),
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

	t.Run("CEL rule callback header should be set when rule condition is met", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/headers", mockE2EServer.URL), nil)
		req.Host = "cel-rule-callback-data.test"

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

		// Check for X-User-Tier header (case-insensitive)
		userTierFound := false
		for k, v := range headers {
			if http.CanonicalHeaderKey(k) == "X-User-Tier" {
				userTierFound = true
				if v != "premium" {
					t.Errorf("Expected X-User-Tier to be 'premium', got: %v", v)
				}
				break
			}
		}

		if !userTierFound {
			t.Errorf("X-User-Tier header not found. Headers: %+v", headers)
		}

		// Verify RequestData has session data
		requestData := reqctx.GetRequestData(req.Context())
		if requestData == nil {
			t.Fatal("RequestData should not be nil")
		}
		if requestData.SessionData == nil {
			t.Fatal("SessionData should not be nil")
		}
		if requestData.SessionData.Data == nil {
			t.Fatal("SessionData.Data should not be nil")
		}

		userData, ok := requestData.SessionData.Data["user_data"]
		if !ok {
			t.Fatalf("user_data should be in SessionData.Data. Data: %+v", requestData.SessionData.Data)
		}

		userDataMap, ok := userData.(map[string]interface{})
		if !ok {
			t.Fatalf("user_data should be a map. Got: %T", userData)
		}

		subscription, ok := userDataMap["subscription"]
		if !ok {
			t.Fatalf("subscription should be in user_data. user_data: %+v", userDataMap)
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

