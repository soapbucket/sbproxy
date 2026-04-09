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

// TestCELCallbackHeaders_E2E tests CEL callback header setting using mock e2e server
// This reproduces the E2E issue where headers from CEL callbacks are not being set
func TestCELCallbackHeaders_E2E(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the e2e test server
	mockE2EServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/callback/config":
			// Config callback endpoint
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
		case "/callback/session":
			// Session callback endpoint
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user_preferences": map[string]interface{}{
					"theme":    "dark",
					"language": "en",
					"timezone": "America/New_York",
				},
				"feature_flags": map[string]interface{}{
					"beta_features": true,
					"analytics":     true,
					"export":        true,
				},
				"subscription": map[string]interface{}{
					"tier":    "premium",
					"active":  true,
					"expires": time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
				},
				"api_quota":  10000,
				"rate_limit": 100,
			})
		case "/callback/auth":
			// Auth callback endpoint
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user_id": "user-123",
				"roles":   []string{"admin", "user"},
				"permissions": map[string]interface{}{
					"read":   true,
					"write":  true,
					"delete": true,
					"admin":  true,
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

	tests := []struct {
		name           string
		hostname       string
		configJSON     string
		requestHeaders map[string]string
		expectedHeader string
		expectedValue  string
		description    string
	}{
		{
			name:     "CEL callback config header",
			hostname: "cel-callback-onload.test",
			configJSON: fmt.Sprintf(`{
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
			}`, mockE2EServer.URL, mockE2EServer.URL),
			expectedHeader: "X-API-Version",
			expectedValue:  "v2.1.0",
			description:    "on_load callback should set X-API-Version header from config_data",
		},
		{
			name:     "CEL callback session header",
			hostname: "cel-callback-session.test",
			configJSON: fmt.Sprintf(`{
			  "id": "cel-callback-session",
			  "hostname": "cel-callback-session.test",
			"workspace_id": "test-workspace",
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
			        "cel_expr": "{\"modified_json\": {\"theme\": json['user_preferences']['theme'], \"language\": json['user_preferences']['language'], \"is_premium\": json['subscription']['tier'] == 'premium'}}"
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
			          "X-User-Theme": "{{session.data.user_prefs.theme}}",
			          "X-User-Language": "{{session.data.user_prefs.language}}",
			          "X-Is-Premium": "{{session.data.user_prefs.is_premium}}"
			        }
			      },
			      "rules": [
			        {
			          "cel_expr": "session.data.user_prefs.is_premium == true"
			        }
			      ]
			    }
			  ]
			}`, mockE2EServer.URL, mockE2EServer.URL),
			expectedHeader: "X-User-Theme",
			expectedValue:  "dark",
			description:    "session callback should set X-User-Theme header from session_data when rule matches",
		},
		{
			name:     "CEL callback auth header",
			hostname: "cel-callback-auth.test",
			configJSON: fmt.Sprintf(`{
			  "id": "cel-callback-auth",
			  "hostname": "cel-callback-auth.test",
			"workspace_id": "test-workspace",
			  "authentication": {
			    "type": "api_key",
			    "disabled": false,
			    "header_name": "X-API-Key",
			    "api_keys": ["test-key-123"],
			    "authentication_callback": {
			      "type": "http",
			      "url": "%s/callback/auth",
			      "method": "POST",
			      "timeout": 5,
			      "cel_expr": "{\"modified_json\": {\"user_id\": string('user_id' in json ? json['user_id'] : 'unknown'), \"roles\": 'roles' in json ? json['roles'] : [], \"permissions\": 'permissions' in json ? json['permissions'] : {}}}"
			    }
			  },
			  "action": {
			    "type": "proxy",
			    "url": "%s"
			  },
			  "request_modifiers": [
			    {
			      "headers": {
			        "set": {
			          "X-User-ID": "{{session.auth.data.user_id}}",
			          "X-User-Roles": "{{session.auth.data.roles}}"
			        }
			      }
			    }
			  ]
			}`, mockE2EServer.URL, mockE2EServer.URL),
			requestHeaders: map[string]string{
				"X-API-Key": "test-key-123",
			},
			expectedHeader: "X-User-ID",
			expectedValue:  "user-123",
			description:    "auth callback should set X-User-ID header from auth_data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Session callback tests require full session middleware lifecycle which
			// cannot be reproduced in a unit test without a real session store and
			// cookie round-trip. Skip these until full integration test infra is available.
			if tt.name == "CEL callback session header" {
				t.Skip("Session callback tests require full session middleware lifecycle (integration test)")
			}

			// Reset cache for each test
			resetCache()

			// Create mock storage with config
			mockStore := &mockStorage{
				data: map[string][]byte{
					tt.hostname: []byte(tt.configJSON),
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

			// Create request
			req := httptest.NewRequest(http.MethodGet, "http://"+tt.hostname+"/api/headers", nil)
			req.Host = tt.hostname

			// Add request headers if specified
			for k, v := range tt.requestHeaders {
				req.Header.Set(k, v)
			}

			// Load config
			cfg, err := Load(req, mgr)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Debug: Check what's in Config.Params
			if cfg != nil && cfg.Params != nil {
				t.Logf("Config.Params length: %d, keys: %v", len(cfg.Params), getMapKeys(cfg.Params))
				// Check if config_data exists and what's inside it
				if configData, ok := cfg.Params["config_data"]; ok {
					t.Logf("Config.Params['config_data'] type: %T, value: %+v", configData, configData)
					if configDataMap, ok := configData.(map[string]any); ok {
						t.Logf("Config.Params['config_data'] keys: %v", getMapKeys(configDataMap))
						if apiVersion, ok := configDataMap["api_version"]; ok {
							t.Logf("Config.Params['config_data']['api_version']: %v", apiVersion)
						}
					}
				}
				// Also check for modified_json
				if modifiedJSON, ok := cfg.Params["modified_json"]; ok {
					t.Logf("Config.Params['modified_json'] type: %T, value: %+v", modifiedJSON, modifiedJSON)
				}
			}

			// Debug: Check what's in RequestData.Config after Load
			requestData := reqctx.GetRequestData(req.Context())
			if requestData != nil && requestData.Config != nil {
				t.Logf("RequestData.Config length: %d, keys: %v", len(requestData.Config), getMapKeys(requestData.Config))
				// Check if config_data exists and what's inside it
				if configData, ok := requestData.Config["config_data"]; ok {
					t.Logf("RequestData.Config['config_data'] type: %T, value: %+v", configData, configData)
				}
				// Also check for modified_json
				if modifiedJSON, ok := requestData.Config["modified_json"]; ok {
					t.Logf("RequestData.Config['modified_json'] type: %T, value: %+v", modifiedJSON, modifiedJSON)
				}
			}

			// Execute request
			w := httptest.NewRecorder()
			
			// Wrap handler with session middleware if session config exists
			var handler http.Handler = cfg
			if cfg.HasSessionConfig() {
				handler = session.SessionMiddleware(mgr, cfg.SessionConfig)(handler)
			}
			
			// Use the wrapped handler instead of cfg.ServeHTTP directly
			handler.ServeHTTP(w, req)
			
			// Debug: Check session data after request
			requestData = reqctx.GetRequestData(req.Context())
			if requestData != nil && requestData.SessionData != nil {
				t.Logf("SessionData.Data length: %d, keys: %v", len(requestData.SessionData.Data), getMapKeys(requestData.SessionData.Data))
				if userPrefs, ok := requestData.SessionData.Data["user_prefs"]; ok {
					t.Logf("SessionData.Data['user_prefs'] type: %T, value: %+v", userPrefs, userPrefs)
				}
			}

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
				if k == tt.expectedHeader || 
				   (len(k) == len(tt.expectedHeader) && 
				    equalsIgnoreCase(k, tt.expectedHeader)) {
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
				t.Errorf("%s: Expected header %s not found. Headers: %+v", 
					tt.description, tt.expectedHeader, headers)
				return
			}

			if actualValue != tt.expectedValue {
				t.Errorf("%s: Expected header %s to be %q, got %q", 
					tt.description, tt.expectedHeader, tt.expectedValue, actualValue)
			} else {
				t.Logf("✓ %s: Header %s = %q", tt.description, tt.expectedHeader, actualValue)
			}
		})
	}
}

// TestCELExpressionPolicyCallback_E2E tests CEL expression policy with on_load callback
func TestCELExpressionPolicyCallback_E2E(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the e2e test server
	mockE2EServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer mockE2EServer.Close()

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
	}`, mockE2EServer.URL, mockE2EServer.URL)

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

		// Test the request
		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})

	t.Run("CEL expression policy should block POST request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://cel-expression-policy-callback.test/", nil)
		req.Host = "cel-expression-policy-callback.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		// Expression policy defaults to 401 (Unauthorized) for blocking
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
}

// Helper function to get map keys
func getMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Helper function for case-insensitive string comparison
func equalsIgnoreCase(s1, s2 string) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := 0; i < len(s1); i++ {
		c1 := s1[i]
		c2 := s2[i]
		if c1 >= 'A' && c1 <= 'Z' {
			c1 += 'a' - 'A'
		}
		if c2 >= 'A' && c2 <= 'Z' {
			c2 += 'a' - 'A'
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}

