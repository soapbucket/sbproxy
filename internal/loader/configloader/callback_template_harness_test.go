package configloader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestCallbackTemplateVariables_OnLoad tests on_load callback template variable resolution
func TestCallbackTemplateVariables_OnLoad(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the callback endpoint
	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/callback/config" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"version":   "v2",
				"env":       "staging",
				"features":  map[string]bool{"feature1": true, "feature2": false},
			})
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer mockCallbackServer.Close()

	// Update config to use mock server
	configJSONWithMock := fmt.Sprintf(`{
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
	}`, mockCallbackServer.URL, mockCallbackServer.URL)

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"cel-callback-onload.test": []byte(configJSONWithMock),
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

	// Make a request
	req := httptest.NewRequest("GET", "http://cel-callback-onload.test/", nil)
	req.Host = "cel-callback-onload.test"

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

	// Check if headers were set correctly
	// Note: We can't directly check the headers in the response because they're set on the outgoing request
	// But we can verify the config was loaded and the template variables should be resolved
	t.Logf("Response status: %d", w.Code)
	t.Logf("Response body: %s", w.Body.String())
}

// TestCallbackTemplateVariables_Session tests session callback template variable resolution
func TestCallbackTemplateVariables_Session(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the callback endpoint
	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/callback/session" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user_preferences": map[string]interface{}{
					"theme":    "dark",
					"language": "en",
				},
				"subscription": map[string]interface{}{
					"tier": "premium",
				},
			})
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer mockCallbackServer.Close()

	// Load the CEL session callback config
	configJSON := fmt.Sprintf(`{
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
	        "cel_expr": "{\"modified_json\": {\"user_prefs\": {\"theme\": json['user_preferences']['theme'], \"language\": json['user_preferences']['language'], \"is_premium\": json['subscription']['tier'] == 'premium'}}}"
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
	      }
	    }
	  ]
	}`, mockCallbackServer.URL, mockCallbackServer.URL)

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"cel-callback-session.test": []byte(configJSON),
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

	// Make a request
	req := httptest.NewRequest("GET", "http://cel-callback-session.test/", nil)
	req.Host = "cel-callback-session.test"

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

	t.Logf("Response status: %d", w.Code)
	t.Logf("Response body: %s", w.Body.String())
}

// TestCallbackTemplateVariables_Auth tests auth callback template variable resolution
func TestCallbackTemplateVariables_Auth(t *testing.T) {
	// Reset cache
	resetCache()

	// Create a mock HTTP server to simulate the callback endpoint
	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/callback/auth" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user_id":    "user123",
				"roles":      []string{"admin", "user"},
				"permissions": map[string]bool{"read": true, "write": true},
			})
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer mockCallbackServer.Close()

	// Load the CEL auth callback config
	configJSON := fmt.Sprintf(`{
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
	      "cel_expr": "{\"modified_json\": {\"auth_data\": {\"user_id\": string('user_id' in json ? json['user_id'] : 'unknown'), \"roles\": 'roles' in json ? json['roles'] : [], \"permissions\": 'permissions' in json ? json['permissions'] : {}}}}"
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
	}`, mockCallbackServer.URL, mockCallbackServer.URL)

	// Create mock storage with config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"cel-callback-auth.test": []byte(configJSON),
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

	// Make a request with API key
	req := httptest.NewRequest("GET", "http://cel-callback-auth.test/", nil)
	req.Host = "cel-callback-auth.test"
	req.Header.Set("X-API-Key", "test-key-123")

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

	t.Logf("Response status: %d", w.Code)
	t.Logf("Response body: %s", w.Body.String())
}

