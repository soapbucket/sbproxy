package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// Helper function to set auth data in request context for testing
func setAuthDataInRequest(r *http.Request, authData *reqctx.AuthData) {
	requestData := reqctx.GetRequestData(r.Context())
	if requestData == nil {
		requestData = reqctx.NewRequestData()
	}
	if requestData.SessionData == nil {
		requestData.SessionData = &reqctx.SessionData{}
	}
	requestData.SessionData.AuthData = authData
	*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))
}

func TestNewOAuthConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
		check   func(*testing.T, *OAuthAuthConfig)
	}{
		{
			name: "valid google config",
			data: `{
				"type": "oauth",
				"provider": "google",
				"client_id": "test-client-id",
				"client_secret": "test-client-secret",
				"redirect_url": "https://example.com/callback"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *OAuthAuthConfig) {
				assert.Equal(t, "google", cfg.Provider)
				assert.Equal(t, "test-client-id", cfg.ClientID)
				assert.Equal(t, "test-client-secret", cfg.ClientSecret)
				assert.NotNil(t, cfg.oauth2Config)
				// Check it uses provider preset URL
				assert.Contains(t, cfg.oauth2Config.Endpoint.AuthURL, "accounts.google.com")
			},
		},
		{
			name: "valid github config",
			data: `{
				"type": "oauth",
				"provider": "github",
				"client_id": "test-client-id",
				"client_secret": "test-client-secret",
				"redirect_url": "https://example.com/callback"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *OAuthAuthConfig) {
				assert.Equal(t, "github", cfg.Provider)
				assert.NotNil(t, cfg.oauth2Config)
				assert.Contains(t, cfg.oauth2Config.Endpoint.AuthURL, "github.com")
				assert.Contains(t, cfg.oauth2Config.Scopes, "user:email")
			},
		},
		{
			name: "valid custom provider",
			data: `{
				"type": "oauth",
				"client_id": "test-client-id",
				"client_secret": "test-client-secret",
				"redirect_url": "https://example.com/callback",
				"auth_url": "https://auth.example.com/authorize",
				"token_url": "https://auth.example.com/token"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *OAuthAuthConfig) {
				assert.NotNil(t, cfg.oauth2Config)
				assert.Equal(t, "https://auth.example.com/authorize", cfg.oauth2Config.Endpoint.AuthURL)
				assert.Equal(t, "https://auth.example.com/token", cfg.oauth2Config.Endpoint.TokenURL)
			},
		},
		{
			name: "custom provider missing auth_url",
			data: `{
				"type": "oauth",
				"client_id": "test-client-id",
				"client_secret": "test-client-secret",
				"redirect_url": "https://example.com/callback",
				"token_url": "https://auth.example.com/token"
			}`,
			wantErr: true,
		},
		{
			name: "unsupported provider",
			data: `{
				"type": "oauth",
				"provider": "unknown",
				"client_id": "test-client-id",
				"client_secret": "test-client-secret",
				"redirect_url": "https://example.com/callback"
			}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			data:    `{invalid}`,
			wantErr: true,
		},
		{
			name: "custom scopes",
			data: `{
				"type": "oauth",
				"provider": "google",
				"client_id": "test-client-id",
				"client_secret": "test-client-secret",
				"redirect_url": "https://example.com/callback",
				"scopes": ["custom-scope-1", "custom-scope-2"]
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *OAuthAuthConfig) {
				assert.Equal(t, []string{"custom-scope-1", "custom-scope-2"}, cfg.oauth2Config.Scopes)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewOAuthConfig([]byte(tt.data))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, config)

			oauthConfig, ok := config.(*OAuthAuthConfig)
			require.True(t, ok)

			if tt.check != nil {
				tt.check(t, oauthConfig)
			}
		})
	}
}

func TestOAuthAuthConfig_GetPaths(t *testing.T) {
	tests := []struct {
		name         string
		config       *OAuthAuthConfig
		wantCallback string
		wantLogin    string
		wantLogout   string
	}{
		{
			name:         "default paths",
			config:       &OAuthAuthConfig{},
			wantCallback: DefaultOAuthCallbackPath,
			wantLogin:    DefaultOAuthLoginPath,
			wantLogout:   DefaultOAuthLogoutPath,
		},
		{
			name: "custom paths",
			config: &OAuthAuthConfig{
				OAuthConfig: OAuthConfig{
					CallbackPath: "/custom/callback",
					LoginPath:    "/custom/login",
					LogoutPath:   "/custom/logout",
				},
			},
			wantCallback: "/custom/callback",
			wantLogin:    "/custom/login",
			wantLogout:   "/custom/logout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantCallback, tt.config.getCallbackPath())
			assert.Equal(t, tt.wantLogin, tt.config.getLoginPath())
			assert.Equal(t, tt.wantLogout, tt.config.getLogoutPath())
		})
	}
}

func TestOAuthAuthConfig_Login(t *testing.T) {
	config := &OAuthAuthConfig{
		OAuthConfig: OAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeOAuth,
			},
		},
		oauth2Config: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://example.com/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.example.com/authorize",
				TokenURL: "https://auth.example.com/token",
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/login", nil)
	w := httptest.NewRecorder()

	config.login(w, req)

	// Check redirect status
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)

	// Check Location header contains auth URL
	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://auth.example.com/authorize")
	assert.Contains(t, location, "client_id=test-client")

	// Check state cookie was set
	cookies := w.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "oauth_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "oauth_state cookie should be set")
	assert.NotEmpty(t, stateCookie.Value)
	assert.True(t, stateCookie.HttpOnly)
	assert.True(t, stateCookie.Secure)
	assert.Equal(t, 600, stateCookie.MaxAge)
}

func TestOAuthAuthConfig_Callback(t *testing.T) {
	config := &OAuthAuthConfig{
		OAuthConfig: OAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeOAuth,
			},
			Provider: "google",
		},
		oauth2Config: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://example.com/callback",
		},
	}

	t.Run("missing state parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=test-code", nil)
		w := httptest.NewRecorder()

		config.callback(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("state mismatch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=test-code&state=state1", nil)
		req.AddCookie(&http.Cookie{
			Name:  "oauth_state",
			Value: "state2",
		})
		w := httptest.NewRecorder()

		config.callback(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	// Note: Full callback test would require mocking the OAuth2 Exchange and HTTP client
	// which is complex. Testing the path logic and state validation is more practical.
}

func TestOAuthAuthConfig_Logout(t *testing.T) {
	authData := &reqctx.AuthData{
		Type: "oauth",
		Data: map[string]any{
			"user_id": "test-user",
		},
	}

	config := &OAuthAuthConfig{
		OAuthConfig: OAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeOAuth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/logout", nil)
	setAuthDataInRequest(req, authData)
	w := httptest.NewRecorder()

	config.logout(w, req)

	// Check redirect
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))

	// Check data was deleted from request context
	requestData := reqctx.GetRequestData(req.Context())
	assert.NotNil(t, requestData)
	if requestData.SessionData != nil {
		assert.Nil(t, requestData.SessionData.AuthData)
	}
}

func TestOAuthAuthConfig_Authenticate(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name           string
		setupConfig    func() *OAuthAuthConfig
		setupRequest   func() *http.Request
		wantStatusCode int
		wantLocation   string
	}{
		{
			name: "disabled service",
			setupConfig: func() *OAuthAuthConfig {
				return &OAuthAuthConfig{
					OAuthConfig: OAuthConfig{
						BaseAuthConfig: BaseAuthConfig{
							AuthType: AuthTypeOAuth,
							Disabled: true,
						},
					},
				}
			},
			setupRequest: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantStatusCode: http.StatusServiceUnavailable,
		},
		{
			name: "force authentication without session",
			setupConfig: func() *OAuthAuthConfig {
				return &OAuthAuthConfig{
					OAuthConfig: OAuthConfig{
						BaseAuthConfig: BaseAuthConfig{
							AuthType: AuthTypeOAuth,
						},
						ForceAuthentication: true,
					},
				}
			},
			setupRequest: func() *http.Request {
				// No auth data in request - should redirect to login
				return httptest.NewRequest(http.MethodGet, "/protected", nil)
			},
			wantStatusCode: http.StatusFound,
			wantLocation:   DefaultOAuthLoginPath,
		},
		{
			name: "valid session",
			setupConfig: func() *OAuthAuthConfig {
				return &OAuthAuthConfig{
					OAuthConfig: OAuthConfig{
						BaseAuthConfig: BaseAuthConfig{
							AuthType: AuthTypeOAuth,
						},
					},
				}
			},
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				setAuthDataInRequest(req, &reqctx.AuthData{
					Type: "oauth",
					Data: map[string]any{
						"user_id": "test-user",
					},
				})
				return req
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "login path route",
			setupConfig: func() *OAuthAuthConfig {
				return &OAuthAuthConfig{
					OAuthConfig: OAuthConfig{
						BaseAuthConfig: BaseAuthConfig{
							AuthType: AuthTypeOAuth,
						},
					},
					oauth2Config: &oauth2.Config{
						Endpoint: oauth2.Endpoint{
							AuthURL: "https://auth.example.com/authorize",
						},
					},
				}
			},
			setupRequest: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, DefaultOAuthLoginPath, nil)
			},
			wantStatusCode: http.StatusTemporaryRedirect,
		},
		{
			name: "logout path route",
			setupConfig: func() *OAuthAuthConfig {
				return &OAuthAuthConfig{
					OAuthConfig: OAuthConfig{
						BaseAuthConfig: BaseAuthConfig{
							AuthType: AuthTypeOAuth,
						},
					},
				}
			},
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, DefaultOAuthLogoutPath, nil)
				setAuthDataInRequest(req, &reqctx.AuthData{
					Type: "oauth",
				})
				return req
			},
			wantStatusCode: http.StatusTemporaryRedirect,
			wantLocation:   "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			req := tt.setupRequest()
			w := httptest.NewRecorder()

			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatusCode, w.Code)
			if tt.wantLocation != "" {
				location := w.Header().Get("Location")
				assert.Contains(t, location, tt.wantLocation)
			}
		})
	}
}

func TestOAuthAuthConfig_AuthDataMethods(t *testing.T) {
	t.Run("getAuthData with valid session", func(t *testing.T) {
		config := &OAuthAuthConfig{}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		authData := &reqctx.AuthData{
			Type: "oauth",
			Data: map[string]any{
				"user_id": "test-user",
			},
		}
		setAuthDataInRequest(req, authData)

		data, err := config.getAuthData(req)

		assert.NoError(t, err)
		assert.NotNil(t, data)
		assert.Equal(t, "oauth", data.Type)
		assert.Equal(t, "test-user", data.Data["user_id"])
	})

	t.Run("getAuthData without session", func(t *testing.T) {
		config := &OAuthAuthConfig{}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// No auth data set

		_, err := config.getAuthData(req)
		assert.ErrorIs(t, err, ErrNoAuthData)
	})

	t.Run("deleteAuthData", func(t *testing.T) {
		config := &OAuthAuthConfig{}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		authData := &reqctx.AuthData{
			Type: "oauth",
			Data: map[string]any{
				"user_id": "test-user",
			},
		}
		setAuthDataInRequest(req, authData)

		// Verify auth data exists before deletion
		requestData := reqctx.GetRequestData(req.Context())
		assert.NotNil(t, requestData.SessionData.AuthData)

		err := config.deleteAuthData(req, authData)
		assert.NoError(t, err)

		// Verify auth data was deleted
		requestData = reqctx.GetRequestData(req.Context())
		if requestData.SessionData != nil {
			assert.Nil(t, requestData.SessionData.AuthData)
		}
	})

	t.Run("deleteAuthData without session", func(t *testing.T) {
		config := &OAuthAuthConfig{}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// No session data

		err := config.deleteAuthData(req, &reqctx.AuthData{})
		assert.NoError(t, err) // Should not error even if no session
	})
}

func TestOAuthAuthConfig_RedirectToLogin(t *testing.T) {
	config := &OAuthAuthConfig{
		OAuthConfig: OAuthConfig{
			LoginPath: "/custom/login",
		},
	}

	tests := []struct {
		name         string
		requestURL   string
		wantLocation string
	}{
		{
			name:         "simple path",
			requestURL:   "/protected",
			wantLocation: "/custom/login",
		},
		{
			name:         "with query params",
			requestURL:   "/protected?param1=value1&param2=value2",
			wantLocation: "/custom/login?param1=value1&param2=value2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.requestURL, nil)
			w := httptest.NewRecorder()

			config.redirectToLogin(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, tt.wantLocation, w.Header().Get("Location"))
		})
	}
}

func TestGenerateRandomState(t *testing.T) {
	// Test that state generation produces unique values
	state1, err1 := generateRandomState()
	require.NoError(t, err1)
	time.Sleep(1 * time.Millisecond) // Ensure different timestamp
	state2, err2 := generateRandomState()
	require.NoError(t, err2)

	assert.NotEmpty(t, state1)
	assert.NotEmpty(t, state2)
	assert.NotEqual(t, state1, state2, "states should be unique")

	// Test that states are properly base64 encoded
	assert.Greater(t, len(state1), 40, "state should be at least 40 characters (32 bytes base64 encoded)")
	assert.Greater(t, len(state2), 40, "state should be at least 40 characters (32 bytes base64 encoded)")
}

func TestCreateOAuth2Config(t *testing.T) {
	tests := []struct {
		name    string
		config  *OAuthAuthConfig
		wantErr bool
		check   func(*testing.T, *oauth2.Config)
	}{
		{
			name: "google provider",
			config: &OAuthAuthConfig{
				OAuthConfig: OAuthConfig{
					Provider:     "google",
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/callback",
				},
			},
			wantErr: false,
			check: func(t *testing.T, cfg *oauth2.Config) {
				assert.Equal(t, "test-id", cfg.ClientID)
				assert.Equal(t, "test-secret", cfg.ClientSecret)
				assert.Equal(t, "https://example.com/callback", cfg.RedirectURL)
				assert.Contains(t, cfg.Scopes, "openid")
				assert.Contains(t, cfg.Scopes, "email")
				assert.Contains(t, cfg.Scopes, "profile")
			},
		},
		{
			name: "github provider",
			config: &OAuthAuthConfig{
				OAuthConfig: OAuthConfig{
					Provider:     "github",
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/callback",
				},
			},
			wantErr: false,
			check: func(t *testing.T, cfg *oauth2.Config) {
				assert.Contains(t, cfg.Scopes, "user:email")
			},
		},
		{
			name: "custom provider valid",
			config: &OAuthAuthConfig{
				OAuthConfig: OAuthConfig{
					Provider:     "custom",
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/callback",
					AuthURL:      "https://auth.example.com/authorize",
					TokenURL:     "https://auth.example.com/token",
				},
			},
			wantErr: false,
			check: func(t *testing.T, cfg *oauth2.Config) {
				assert.Equal(t, "https://auth.example.com/authorize", cfg.Endpoint.AuthURL)
				assert.Equal(t, "https://auth.example.com/token", cfg.Endpoint.TokenURL)
			},
		},
		{
			name: "custom provider missing auth_url",
			config: &OAuthAuthConfig{
				OAuthConfig: OAuthConfig{
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/callback",
					TokenURL:     "https://auth.example.com/token",
				},
			},
			wantErr: true,
		},
		{
			name: "unsupported provider",
			config: &OAuthAuthConfig{
				OAuthConfig: OAuthConfig{
					Provider:     "unsupported",
					ClientID:     "test-id",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/callback",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply provider defaults if provider is set
			if tt.config.Provider != "" {
				_ = ApplyProviderDefaults(&tt.config.OAuthConfig, nil)
			}

			cfg, err := createOAuth2Config(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, cfg)

			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestOAuthAuthConfig_GetAuthDataFromToken(t *testing.T) {
	// Note: This would require mocking HTTP responses from Google/GitHub APIs
	// For now, we test the structure and error handling
	config := &OAuthAuthConfig{
		OAuthConfig: OAuthConfig{
			Provider: "unknown-provider",
		},
		oauth2Config: &oauth2.Config{},
	}

	token := &oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	ctx := context.Background()
	data, err := config.getAuthDataFromToken(ctx, token)

	// Should not error for unknown provider, just return empty results
	assert.NoError(t, err)
	assert.NotNil(t, data)
	assert.Equal(t, "oauth", data.Type)
	assert.Equal(t, "unknown-provider", data.Data["provider"])
}

func TestOAuthAuthConfig_Init(t *testing.T) {
	oauthConfig := &OAuthAuthConfig{}
	testConfig := &Config{}

	err := oauthConfig.Init(testConfig)

	assert.NoError(t, err)
	assert.Equal(t, testConfig, oauthConfig.cfg)
}

func TestOAuthAuthConfig_CallbackMethods(t *testing.T) {
	t.Run("callAuthenticationCallback with nil callback", func(t *testing.T) {
		config := &OAuthAuthConfig{
			OAuthConfig: OAuthConfig{
				BaseAuthConfig: BaseAuthConfig{
					AuthenticationCallback: nil,
				},
			},
		}

		data := &reqctx.AuthData{
			Data: make(map[string]any),
		}

		err := config.callAuthenticationCallback(context.Background(), data)
		assert.NoError(t, err)
	})

	t.Run("callLogoutCallback with nil callback", func(t *testing.T) {
		config := &OAuthAuthConfig{
			OAuthConfig: OAuthConfig{
				LogoutCallback: nil,
			},
		}

		data := &reqctx.AuthData{
			Data: make(map[string]any),
		}

		err := config.callLogoutCallback(context.Background(), data)
		assert.NoError(t, err)
	})
}
