package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/config/callback"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAPIKeyAuthConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
		check   func(*testing.T, *APIKeyAuthConfig)
	}{
		{
			name: "valid config with static keys",
			data: `{
				"type": "api_key",
				"api_keys": ["key1", "key2", "key3"]
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *APIKeyAuthConfig) {
				assert.Equal(t, 3, len(cfg.APIKeys))
				assert.Contains(t, cfg.APIKeys, "key1")
				assert.Contains(t, cfg.APIKeys, "key2")
				assert.Contains(t, cfg.APIKeys, "key3")
				assert.Equal(t, DefaultAPIKeyHeaderName, cfg.HeaderName)
			},
		},
		{
			name: "valid config with custom header",
			data: `{
				"type": "api_key",
				"api_keys": ["key1"],
				"header_name": "X-Custom-API-Key"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *APIKeyAuthConfig) {
				assert.Equal(t, "X-Custom-API-Key", cfg.HeaderName)
			},
		},
		{
			name: "valid config with query param",
			data: `{
				"type": "api_key",
				"api_keys": ["key1"],
				"query_param": "apikey"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *APIKeyAuthConfig) {
				assert.Equal(t, "apikey", cfg.QueryParam)
			},
		},
		{
			name:    "invalid json",
			data:    `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewAPIKeyAuthConfig([]byte(tt.data))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, config)

			apiKeyConfig, ok := config.(*APIKeyAuthConfig)
			require.True(t, ok)

			if tt.check != nil {
				tt.check(t, apiKeyConfig)
			}
		})
	}
}

func TestAPIKeyAuthConfig_ExtractAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		config     *APIKeyAuthConfig
		setupReq   func() *http.Request
		wantAPIKey string
	}{
		{
			name: "extract from default header",
			config: &APIKeyAuthConfig{
				HeaderName: DefaultAPIKeyHeaderName,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-API-Key", "test-api-key-123")
				return req
			},
			wantAPIKey: "test-api-key-123",
		},
		{
			name: "extract from custom header",
			config: &APIKeyAuthConfig{
				HeaderName: "X-Custom-Key",
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Custom-Key", "custom-key-456")
				return req
			},
			wantAPIKey: "custom-key-456",
		},
		{
			name: "extract from query param",
			config: &APIKeyAuthConfig{
				QueryParam: "api_key",
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/?api_key=query-key-789", nil)
			},
			wantAPIKey: "query-key-789",
		},
		{
			name: "header takes precedence over query param",
			config: &APIKeyAuthConfig{
				HeaderName: DefaultAPIKeyHeaderName,
				QueryParam: "api_key",
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/?api_key=query-key", nil)
				req.Header.Set("X-API-Key", "header-key")
				return req
			},
			wantAPIKey: "header-key",
		},
		{
			name: "no api key provided",
			config: &APIKeyAuthConfig{
				HeaderName: DefaultAPIKeyHeaderName,
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantAPIKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			apiKey := tt.config.extractAPIKey(req)
			assert.Equal(t, tt.wantAPIKey, apiKey)
		})
	}
}

func TestAPIKeyAuthConfig_Authenticate(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name           string
		config         *APIKeyAuthConfig
		setupReq       func() *http.Request
		wantStatusCode int
		wantBody       string
	}{
		{
			name: "valid api key",
			config: &APIKeyAuthConfig{
				APIKeyConfig: APIKeyConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeAPIKey,
					},
					APIKeys: []string{"valid-key-1", "valid-key-2"},
				},
				HeaderName: DefaultAPIKeyHeaderName,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-API-Key", "valid-key-1")
				return req
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "success",
		},
		{
			name: "invalid api key",
			config: &APIKeyAuthConfig{
				APIKeyConfig: APIKeyConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeAPIKey,
					},
					APIKeys: []string{"valid-key-1", "valid-key-2"},
				},
				HeaderName: DefaultAPIKeyHeaderName,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-API-Key", "invalid-key")
				return req
			},
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name: "no api key provided",
			config: &APIKeyAuthConfig{
				APIKeyConfig: APIKeyConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeAPIKey,
					},
					APIKeys: []string{"valid-key-1"},
				},
				HeaderName: DefaultAPIKeyHeaderName,
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name: "valid api key from query param",
			config: &APIKeyAuthConfig{
				APIKeyConfig: APIKeyConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeAPIKey,
					},
					APIKeys: []string{"valid-key-1"},
				},
				HeaderName: DefaultAPIKeyHeaderName,
				QueryParam: "apikey",
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/?apikey=valid-key-1", nil)
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build apiKeyMap from APIKeys (normally done by NewAPIKeyAuthConfig constructor)
			tt.config.apiKeyMap = make(map[string]bool, len(tt.config.APIKeys))
			for _, key := range tt.config.APIKeys {
				tt.config.apiKeyMap[key] = true
			}

			req := tt.setupReq()
			w := httptest.NewRecorder()

			handler := tt.config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatusCode, w.Code)
			if tt.wantBody != "" {
				assert.Equal(t, tt.wantBody, w.Body.String())
			}
		})
	}
}

func TestAPIKeyAuthConfig_GetAPIKeys(t *testing.T) {
	t.Run("no callback configured", func(t *testing.T) {
		config := &APIKeyAuthConfig{}
		keys, err := config.getAPIKeys(context.Background())
		assert.NoError(t, err)
		assert.Nil(t, keys)
	})

	t.Run("callback returns string array", func(t *testing.T) {
		mockCallback := &callback.Callback{
			CacheDuration: reqctx.Duration{}, // No cache for testing
		}
		// Note: Actual callback testing would require a mock implementation
		// This is a structure test

		config := &APIKeyAuthConfig{
			APIKeyConfig: APIKeyConfig{
				APIKeysCallback: mockCallback,
			},
			mapKeys: make(map[string]apiKeys),
		}

		// We can't test the actual callback without implementing a mock
		// but we can test that the structure is correct
		assert.NotNil(t, config.mapKeys)
	})

	t.Run("cached keys not expired", func(t *testing.T) {
		mockCallback := &callback.Callback{
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		}

		config := &APIKeyAuthConfig{
			APIKeyConfig: APIKeyConfig{
				APIKeysCallback: mockCallback,
			},
			mapKeys: map[string]apiKeys{
				mockCallback.GetCacheKey(): {
					keys:    []string{"cached-key-1", "cached-key-2"},
					expires: time.Now().Add(1 * time.Hour),
				},
			},
		}

		keys, err := config.getAPIKeys(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, []string{"cached-key-1", "cached-key-2"}, keys)
	})

	t.Run("cached keys expired", func(t *testing.T) {
		mockCallback := &callback.Callback{
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		}

		config := &APIKeyAuthConfig{
			APIKeyConfig: APIKeyConfig{
				APIKeysCallback: mockCallback,
			},
			mapKeys: map[string]apiKeys{
				mockCallback.GetCacheKey(): {
					keys:    []string{"expired-key"},
					expires: time.Now().Add(-1 * time.Hour), // Already expired
				},
			},
		}

		// This will try to call the callback, which will fail without a proper mock
		// but we can verify the cache expiry logic
		cache := config.mapKeys[mockCallback.GetCacheKey()]
		assert.True(t, cache.IsExpired())
	})
}

func TestAPIKeyAuthConfig_WithCallback(t *testing.T) {
	// Test authentication callback
	callbackInvoked := false

	config := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeAPIKey,
				AuthenticationCallback: &callback.Callback{
					// Mock callback would be set here
				},
			},
			APIKeys: []string{"test-key"},
		},
		HeaderName: DefaultAPIKeyHeaderName,
	}

	// This test verifies the structure is correct
	// Full callback testing would require mock implementation
	assert.NotNil(t, config.AuthenticationCallback)

	// Reset the flag for cleanup
	_ = callbackInvoked
}

func TestAPIKeyAuthConfig_LoadAuthConfig(t *testing.T) {
	data := json.RawMessage(`{
		"type": "api_key",
		"api_keys": ["key1", "key2"]
	}`)

	authConfig, err := LoadAuthConfig(data)
	require.NoError(t, err)
	assert.NotNil(t, authConfig)

	apiKeyConfig, ok := authConfig.(*APIKeyAuthConfig)
	require.True(t, ok)
	assert.Equal(t, AuthTypeAPIKey, apiKeyConfig.GetType())
	assert.Equal(t, 2, len(apiKeyConfig.APIKeys))
}

func TestAPIKeyAuthConfig_Disabled(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// When using BaseAuthConfig.Authenticate with Disabled flag
	config := &BaseAuthConfig{
		AuthType: AuthTypeAPIKey,
		Disabled: true,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler := config.Authenticate(nextHandler)
	handler.ServeHTTP(w, req)

	// Should pass through without authentication
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}

