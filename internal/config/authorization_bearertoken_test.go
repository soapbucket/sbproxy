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

func TestNewBearerTokenAuthConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
		check   func(*testing.T, *BearerTokenAuthConfig)
	}{
		{
			name: "valid config with static tokens",
			data: `{
				"type": "bearer_token",
				"tokens": ["token1", "token2", "token3"]
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *BearerTokenAuthConfig) {
				assert.Equal(t, 3, len(cfg.Tokens))
				assert.Contains(t, cfg.Tokens, "token1")
				assert.Contains(t, cfg.Tokens, "token2")
				assert.Contains(t, cfg.Tokens, "token3")
				assert.Equal(t, DefaultBearerTokenHeaderName, cfg.HeaderName)
				assert.Equal(t, DefaultBearerTokenHeaderPrefix, cfg.HeaderPrefix)
			},
		},
		{
			name: "valid config with custom header and prefix",
			data: `{
				"type": "bearer_token",
				"tokens": ["token1"],
				"header_name": "X-Auth-Token",
				"header_prefix": "Token "
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *BearerTokenAuthConfig) {
				assert.Equal(t, "X-Auth-Token", cfg.HeaderName)
				assert.Equal(t, "Token ", cfg.HeaderPrefix)
			},
		},
		{
			name: "valid config with cookie",
			data: `{
				"type": "bearer_token",
				"tokens": ["token1"],
				"cookie_name": "auth_token"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *BearerTokenAuthConfig) {
				assert.Equal(t, "auth_token", cfg.CookieName)
			},
		},
		{
			name: "valid config with query param",
			data: `{
				"type": "bearer_token",
				"tokens": ["token1"],
				"query_param": "access_token"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *BearerTokenAuthConfig) {
				assert.Equal(t, "access_token", cfg.QueryParam)
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
			config, err := NewBearerTokenAuthConfig([]byte(tt.data))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, config)

			bearerTokenConfig, ok := config.(*BearerTokenAuthConfig)
			require.True(t, ok)

			if tt.check != nil {
				tt.check(t, bearerTokenConfig)
			}
		})
	}
}

func TestBearerTokenAuthConfig_ExtractToken(t *testing.T) {
	tests := []struct {
		name      string
		config    *BearerTokenAuthConfig
		setupReq  func() *http.Request
		wantToken string
	}{
		{
			name: "extract from Authorization header with Bearer prefix",
			config: &BearerTokenAuthConfig{
				HeaderName:   DefaultBearerTokenHeaderName,
				HeaderPrefix: DefaultBearerTokenHeaderPrefix,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer test-token-123")
				return req
			},
			wantToken: "test-token-123",
		},
		{
			name: "extract from Authorization header without prefix",
			config: &BearerTokenAuthConfig{
				HeaderName:   DefaultBearerTokenHeaderName,
				HeaderPrefix: "",
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "raw-token-456")
				return req
			},
			wantToken: "raw-token-456",
		},
		{
			name: "extract from custom header with custom prefix",
			config: &BearerTokenAuthConfig{
				HeaderName:   "X-Auth-Token",
				HeaderPrefix: "Token ",
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Auth-Token", "Token custom-token-789")
				return req
			},
			wantToken: "custom-token-789",
		},
		{
			name: "extract from cookie",
			config: &BearerTokenAuthConfig{
				HeaderName: DefaultBearerTokenHeaderName,
				CookieName: "auth_token",
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "auth_token", Value: "cookie-token-abc"})
				return req
			},
			wantToken: "cookie-token-abc",
		},
		{
			name: "extract from query param",
			config: &BearerTokenAuthConfig{
				HeaderName: DefaultBearerTokenHeaderName,
				QueryParam: "access_token",
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/?access_token=query-token-def", nil)
			},
			wantToken: "query-token-def",
		},
		{
			name: "header takes precedence over cookie",
			config: &BearerTokenAuthConfig{
				HeaderName:   DefaultBearerTokenHeaderName,
				HeaderPrefix: DefaultBearerTokenHeaderPrefix,
				CookieName:   "auth_token",
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer header-token")
				req.AddCookie(&http.Cookie{Name: "auth_token", Value: "cookie-token"})
				return req
			},
			wantToken: "header-token",
		},
		{
			name: "cookie takes precedence over query param",
			config: &BearerTokenAuthConfig{
				HeaderName: DefaultBearerTokenHeaderName,
				CookieName: "auth_token",
				QueryParam: "access_token",
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/?access_token=query-token", nil)
				req.AddCookie(&http.Cookie{Name: "auth_token", Value: "cookie-token"})
				return req
			},
			wantToken: "cookie-token",
		},
		{
			name: "no token provided",
			config: &BearerTokenAuthConfig{
				HeaderName: DefaultBearerTokenHeaderName,
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantToken: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			token := tt.config.extractToken(req)
			assert.Equal(t, tt.wantToken, token)
		})
	}
}

func TestBearerTokenAuthConfig_Authenticate(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name           string
		config         *BearerTokenAuthConfig
		setupReq       func() *http.Request
		wantStatusCode int
		wantBody       string
	}{
		{
			name: "valid bearer token",
			config: &BearerTokenAuthConfig{
				BearerTokenConfig: BearerTokenConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBearerToken,
					},
					Tokens: []string{"valid-token-1", "valid-token-2"},
				},
				HeaderName:   DefaultBearerTokenHeaderName,
				HeaderPrefix: DefaultBearerTokenHeaderPrefix,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer valid-token-1")
				return req
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "success",
		},
		{
			name: "invalid bearer token",
			config: &BearerTokenAuthConfig{
				BearerTokenConfig: BearerTokenConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBearerToken,
					},
					Tokens: []string{"valid-token-1", "valid-token-2"},
				},
				HeaderName:   DefaultBearerTokenHeaderName,
				HeaderPrefix: DefaultBearerTokenHeaderPrefix,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer invalid-token")
				return req
			},
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name: "no bearer token provided",
			config: &BearerTokenAuthConfig{
				BearerTokenConfig: BearerTokenConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBearerToken,
					},
					Tokens: []string{"valid-token-1"},
				},
				HeaderName:   DefaultBearerTokenHeaderName,
				HeaderPrefix: DefaultBearerTokenHeaderPrefix,
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name: "valid token from cookie",
			config: &BearerTokenAuthConfig{
				BearerTokenConfig: BearerTokenConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBearerToken,
					},
					Tokens: []string{"valid-token-1"},
				},
				HeaderName:   DefaultBearerTokenHeaderName,
				HeaderPrefix: DefaultBearerTokenHeaderPrefix,
				CookieName:   "auth_token",
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "auth_token", Value: "valid-token-1"})
				return req
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "success",
		},
		{
			name: "valid token from query param",
			config: &BearerTokenAuthConfig{
				BearerTokenConfig: BearerTokenConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBearerToken,
					},
					Tokens: []string{"valid-token-1"},
				},
				HeaderName:   DefaultBearerTokenHeaderName,
				HeaderPrefix: DefaultBearerTokenHeaderPrefix,
				QueryParam:   "access_token",
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/?access_token=valid-token-1", nil)
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestBearerTokenAuthConfig_GetTokens(t *testing.T) {
	t.Run("no callback configured", func(t *testing.T) {
		config := &BearerTokenAuthConfig{}
		tokens, err := config.getTokens(context.Background())
		assert.NoError(t, err)
		assert.Nil(t, tokens)
	})

	t.Run("callback with cache enabled", func(t *testing.T) {
		mockCallback := &callback.Callback{
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		}

		config := &BearerTokenAuthConfig{
			BearerTokenConfig: BearerTokenConfig{
				TokensCallback: mockCallback,
			},
			mapTokens: make(map[string]bearerTokens),
		}

		// We can't test the actual callback without implementing a mock
		// but we can test that the structure is correct
		assert.NotNil(t, config.mapTokens)
	})

	t.Run("cached tokens not expired", func(t *testing.T) {
		mockCallback := &callback.Callback{
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		}

		config := &BearerTokenAuthConfig{
			BearerTokenConfig: BearerTokenConfig{
				TokensCallback: mockCallback,
			},
			mapTokens: map[string]bearerTokens{
				mockCallback.GetCacheKey(): {
					tokens:  []string{"cached-token-1", "cached-token-2"},
					expires: time.Now().Add(1 * time.Hour),
				},
			},
		}

		tokens, err := config.getTokens(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, []string{"cached-token-1", "cached-token-2"}, tokens)
	})

	t.Run("cached tokens expired", func(t *testing.T) {
		mockCallback := &callback.Callback{
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		}

		config := &BearerTokenAuthConfig{
			BearerTokenConfig: BearerTokenConfig{
				TokensCallback: mockCallback,
			},
			mapTokens: map[string]bearerTokens{
				mockCallback.GetCacheKey(): {
					tokens:  []string{"expired-token"},
					expires: time.Now().Add(-1 * time.Hour), // Already expired
				},
			},
		}

		// This will try to call the callback, which will fail without a proper mock
		// but we can verify the cache expiry logic
		cache := config.mapTokens[mockCallback.GetCacheKey()]
		assert.True(t, cache.IsExpired())
	})
}

func TestBearerTokenAuthConfig_WithCallback(t *testing.T) {
	// Test authentication callback
	config := &BearerTokenAuthConfig{
		BearerTokenConfig: BearerTokenConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBearerToken,
				AuthenticationCallback: &callback.Callback{
					// Mock callback would be set here
				},
			},
			Tokens: []string{"test-token"},
		},
		HeaderName:   DefaultBearerTokenHeaderName,
		HeaderPrefix: DefaultBearerTokenHeaderPrefix,
	}

	// This test verifies the structure is correct
	// Full callback testing would require mock implementation
	assert.NotNil(t, config.AuthenticationCallback)
}

func TestBearerTokenAuthConfig_LoadAuthConfig(t *testing.T) {
	data := json.RawMessage(`{
		"type": "bearer_token",
		"tokens": ["token1", "token2"]
	}`)

	authConfig, err := LoadAuthConfig(data)
	require.NoError(t, err)
	assert.NotNil(t, authConfig)

	bearerTokenConfig, ok := authConfig.(*BearerTokenAuthConfig)
	require.True(t, ok)
	assert.Equal(t, AuthTypeBearerToken, bearerTokenConfig.GetType())
	assert.Equal(t, 2, len(bearerTokenConfig.Tokens))
}

func TestBearerTokenAuthConfig_Disabled(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// When using BaseAuthConfig.Authenticate with Disabled flag
	config := &BaseAuthConfig{
		AuthType: AuthTypeBearerToken,
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

func TestBearerTokens_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		tokens  bearerTokens
		wantExp bool
	}{
		{
			name: "not expired",
			tokens: bearerTokens{
				tokens:  []string{"token1"},
				expires: time.Now().Add(1 * time.Hour),
			},
			wantExp: false,
		},
		{
			name: "expired",
			tokens: bearerTokens{
				tokens:  []string{"token1"},
				expires: time.Now().Add(-1 * time.Hour),
			},
			wantExp: true,
		},
		{
			name: "just expired",
			tokens: bearerTokens{
				tokens:  []string{"token1"},
				expires: time.Now().Add(-1 * time.Millisecond),
			},
			wantExp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantExp, tt.tokens.IsExpired())
		})
	}
}

