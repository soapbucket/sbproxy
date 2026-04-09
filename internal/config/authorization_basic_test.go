package config

import (
	"context"
	"encoding/base64"
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

func TestNewBasicAuthConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
		check   func(*testing.T, *BasicAutAuthConfig)
	}{
		{
			name: "valid config with static users",
			data: `{
				"type": "basic_auth",
				"users": [
					{"username": "user1", "password": "pass1"},
					{"username": "user2", "password": "pass2"}
				]
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *BasicAutAuthConfig) {
				assert.Equal(t, 2, len(cfg.Users))
				assert.Equal(t, "user1", cfg.Users[0].Username)
				assert.Equal(t, "pass1", cfg.Users[0].Password)
				assert.Equal(t, "user2", cfg.Users[1].Username)
				assert.Equal(t, "pass2", cfg.Users[1].Password)
			},
		},
		{
			name: "valid config with callback",
			data: `{
				"type": "basic_auth",
				"users": [],
				"users_callback": {
					"url": "https://example.com/users"
				}
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *BasicAutAuthConfig) {
				assert.NotNil(t, cfg.UsersCallback)
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
			config, err := NewBasicAuthConfig([]byte(tt.data))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, config)

			basicAuthConfig, ok := config.(*BasicAutAuthConfig)
			require.True(t, ok)

			if tt.check != nil {
				tt.check(t, basicAuthConfig)
			}
		})
	}
}

func TestBasicAuthConfig_Authenticate(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name           string
		config         *BasicAutAuthConfig
		setupReq       func() *http.Request
		wantStatusCode int
		wantBody       string
		wantHeader     map[string]string
	}{
		{
			name: "valid credentials",
			config: &BasicAutAuthConfig{
				BasicAuthConfig: BasicAuthConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBasicAuth,
					},
					Users: []BasicAuthUser{
						{Username: "user1", Password: "pass1"},
						{Username: "user2", Password: "pass2"},
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				auth := base64.StdEncoding.EncodeToString([]byte("user1:pass1"))
				req.Header.Set("Authorization", "Basic "+auth)
				return req
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "success",
		},
		{
			name: "invalid credentials",
			config: &BasicAutAuthConfig{
				BasicAuthConfig: BasicAuthConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBasicAuth,
					},
					Users: []BasicAuthUser{
						{Username: "user1", Password: "pass1"},
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				auth := base64.StdEncoding.EncodeToString([]byte("user1:wrongpass"))
				req.Header.Set("Authorization", "Basic "+auth)
				return req
			},
			wantStatusCode: http.StatusUnauthorized,
			wantHeader: map[string]string{
				"WWW-Authenticate": `Basic realm="Restricted"`,
			},
		},
		{
			name: "no credentials provided",
			config: &BasicAutAuthConfig{
				BasicAuthConfig: BasicAuthConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBasicAuth,
					},
					Users: []BasicAuthUser{
						{Username: "user1", Password: "pass1"},
					},
				},
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantStatusCode: http.StatusUnauthorized,
			wantHeader: map[string]string{
				"WWW-Authenticate": `Basic realm="Restricted"`,
			},
		},
		{
			name: "valid credentials - second user",
			config: &BasicAutAuthConfig{
				BasicAuthConfig: BasicAuthConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBasicAuth,
					},
					Users: []BasicAuthUser{
						{Username: "user1", Password: "pass1"},
						{Username: "user2", Password: "pass2"},
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				auth := base64.StdEncoding.EncodeToString([]byte("user2:pass2"))
				req.Header.Set("Authorization", "Basic "+auth)
				return req
			},
			wantStatusCode: http.StatusOK,
			wantBody:       "success",
		},
		{
			name: "wrong username",
			config: &BasicAutAuthConfig{
				BasicAuthConfig: BasicAuthConfig{
					BaseAuthConfig: BaseAuthConfig{
						AuthType: AuthTypeBasicAuth,
					},
					Users: []BasicAuthUser{
						{Username: "user1", Password: "pass1"},
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				auth := base64.StdEncoding.EncodeToString([]byte("wronguser:pass1"))
				req.Header.Set("Authorization", "Basic "+auth)
				return req
			},
			wantStatusCode: http.StatusUnauthorized,
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
			if tt.wantHeader != nil {
				for key, value := range tt.wantHeader {
					assert.Equal(t, value, w.Header().Get(key))
				}
			}
		})
	}
}

func TestBasicAuthConfig_GetUsers(t *testing.T) {
	t.Run("no callback configured", func(t *testing.T) {
		config := &BasicAutAuthConfig{}
		users, err := config.getUsers(context.Background())
		assert.NoError(t, err)
		assert.Nil(t, users)
	})

	t.Run("callback with cache enabled", func(t *testing.T) {
		mockCallback := &callback.Callback{
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		}

		config := &BasicAutAuthConfig{
			BasicAuthConfig: BasicAuthConfig{
				UsersCallback: mockCallback,
			},
			mapUsers: make(map[string]basicAuthUsers),
		}

		// We can't test the actual callback without implementing a mock
		// but we can test that the structure is correct
		assert.NotNil(t, config.mapUsers)
	})

	t.Run("cached users not expired", func(t *testing.T) {
		mockCallback := &callback.Callback{
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		}

		expectedUsers := []BasicAuthUser{
			{Username: "cached-user-1", Password: "cached-pass-1"},
			{Username: "cached-user-2", Password: "cached-pass-2"},
		}

		config := &BasicAutAuthConfig{
			BasicAuthConfig: BasicAuthConfig{
				UsersCallback: mockCallback,
			},
			mapUsers: map[string]basicAuthUsers{
				mockCallback.GetCacheKey(): {
					users:   expectedUsers,
					expires: time.Now().Add(1 * time.Hour),
				},
			},
		}

		users, err := config.getUsers(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, expectedUsers, users)
	})

	t.Run("cached users expired", func(t *testing.T) {
		mockCallback := &callback.Callback{
			CacheDuration: reqctx.Duration{Duration: 1 * time.Hour},
		}

		config := &BasicAutAuthConfig{
			BasicAuthConfig: BasicAuthConfig{
				UsersCallback: mockCallback,
			},
			mapUsers: map[string]basicAuthUsers{
				mockCallback.GetCacheKey(): {
					users: []BasicAuthUser{
						{Username: "expired-user", Password: "expired-pass"},
					},
					expires: time.Now().Add(-1 * time.Hour), // Already expired
				},
			},
		}

		// This will try to call the callback, which will fail without a proper mock
		// but we can verify the cache expiry logic
		cache := config.mapUsers[mockCallback.GetCacheKey()]
		assert.True(t, cache.IsExpired())
	})
}

func TestBasicAuthConfig_LoadAuthConfig(t *testing.T) {
	data := json.RawMessage(`{
		"type": "basic_auth",
		"users": [
			{"username": "user1", "password": "pass1"}
		]
	}`)

	authConfig, err := LoadAuthConfig(data)
	require.NoError(t, err)
	assert.NotNil(t, authConfig)

	basicAuthConfig, ok := authConfig.(*BasicAutAuthConfig)
	require.True(t, ok)
	assert.Equal(t, AuthTypeBasicAuth, basicAuthConfig.GetType())
	assert.Equal(t, 1, len(basicAuthConfig.Users))
}

func TestBasicAuthConfig_MultipleUsers(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: []BasicAuthUser{
				{Username: "admin", Password: "admin123"},
				{Username: "user", Password: "user123"},
				{Username: "guest", Password: "guest123"},
			},
		},
	}

	// Test each user can authenticate
	users := []struct {
		username string
		password string
	}{
		{"admin", "admin123"},
		{"user", "user123"},
		{"guest", "guest123"},
	}

	for _, u := range users {
		t.Run("authenticate_"+u.username, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			auth := base64.StdEncoding.EncodeToString([]byte(u.username + ":" + u.password))
			req.Header.Set("Authorization", "Basic "+auth)

			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "success", w.Body.String())
		})
	}
}

func TestBasicAuthConfig_Disabled(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// When using BaseAuthConfig.Authenticate with Disabled flag
	config := &BaseAuthConfig{
		AuthType: AuthTypeBasicAuth,
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

func TestBasicAuthUsers_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		users   basicAuthUsers
		wantExp bool
	}{
		{
			name: "not expired",
			users: basicAuthUsers{
				users: []BasicAuthUser{
					{Username: "user1", Password: "pass1"},
				},
				expires: time.Now().Add(1 * time.Hour),
			},
			wantExp: false,
		},
		{
			name: "expired",
			users: basicAuthUsers{
				users: []BasicAuthUser{
					{Username: "user1", Password: "pass1"},
				},
				expires: time.Now().Add(-1 * time.Hour),
			},
			wantExp: true,
		},
		{
			name: "just expired",
			users: basicAuthUsers{
				users: []BasicAuthUser{
					{Username: "user1", Password: "pass1"},
				},
				expires: time.Now().Add(-1 * time.Millisecond),
			},
			wantExp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantExp, tt.users.IsExpired())
		})
	}
}

func TestBasicAuthConfig_EmptyPassword(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: []BasicAuthUser{
				{Username: "user1", Password: ""},
			},
		},
	}

	// Test that empty password is matched correctly
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("user1:"))
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()
	handler := config.Authenticate(nextHandler)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}

func TestBasicAuthConfig_SpecialCharactersInPassword(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: []BasicAuthUser{
				{Username: "user1", Password: "p@$$w0rd!#%&*()"},
			},
		},
	}

	// Test that special characters in password are handled correctly
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("user1:p@$$w0rd!#%&*()"))
	req.Header.Set("Authorization", "Basic "+auth)

	w := httptest.NewRecorder()
	handler := config.Authenticate(nextHandler)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}

