package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newIntrospectionServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func introspectionConfigJSON(serverURL string, overrides map[string]any) []byte {
	cfg := map[string]any{
		"type":              "oauth_introspection",
		"introspection_url": serverURL + "/introspect",
		"client_id":         "test-client",
		"client_secret":     "test-secret",
	}
	for k, v := range overrides {
		cfg[k] = v
	}
	data, _ := json.Marshal(cfg)
	return data
}

func TestNewOAuthIntrospectionConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
		check   func(*testing.T, *OAuthIntrospectionImpl)
	}{
		{
			name: "valid config with required fields",
			data: `{
				"type": "oauth_introspection",
				"introspection_url": "https://auth.example.com/introspect",
				"client_id": "my-client",
				"client_secret": "my-secret"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *OAuthIntrospectionImpl) {
				assert.Equal(t, "https://auth.example.com/introspect", cfg.IntrospectionURL)
				assert.Equal(t, "my-client", cfg.ClientID)
				assert.Equal(t, "my-secret", cfg.ClientSecret)
				assert.Equal(t, DefaultIntrospectionHeaderName, cfg.TokenHeaderName)
				assert.Equal(t, DefaultIntrospectionHeaderPrefix, cfg.TokenHeaderPrefix)
			},
		},
		{
			name: "valid config with all options",
			data: `{
				"type": "oauth_introspection",
				"introspection_url": "https://auth.example.com/introspect",
				"client_id": "my-client",
				"client_secret": "my-secret",
				"cache_duration": "120s",
				"timeout": "10s",
				"required_scopes": ["read", "write"],
				"required_audience": "my-api",
				"token_header_name": "X-Token",
				"token_header_prefix": "Token "
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *OAuthIntrospectionImpl) {
				assert.Equal(t, 120*time.Second, cfg.CacheDuration.Duration)
				assert.Equal(t, 10*time.Second, cfg.Timeout.Duration)
				assert.Equal(t, []string{"read", "write"}, cfg.RequiredScopes)
				assert.Equal(t, "my-api", cfg.RequiredAudience)
				assert.Equal(t, "X-Token", cfg.TokenHeaderName)
				assert.Equal(t, "Token ", cfg.TokenHeaderPrefix)
			},
		},
		{
			name:    "missing introspection_url returns error",
			data:    `{"type": "oauth_introspection", "client_id": "c", "client_secret": "s"}`,
			wantErr: true,
		},
		{
			name:    "missing client_id returns error",
			data:    `{"type": "oauth_introspection", "introspection_url": "http://x", "client_secret": "s"}`,
			wantErr: true,
		},
		{
			name:    "missing client_secret returns error",
			data:    `{"type": "oauth_introspection", "introspection_url": "http://x", "client_id": "c"}`,
			wantErr: true,
		},
		{
			name:    "invalid json returns error",
			data:    `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewOAuthIntrospectionConfig([]byte(tt.data))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			cfg, ok := auth.(*OAuthIntrospectionImpl)
			require.True(t, ok)
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestOAuthIntrospection_GetType(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	assert.Equal(t, "oauth_introspection", auth.GetType())
}

func TestOAuthIntrospection_Init(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	cfg := &Config{ID: "test-origin"}
	require.NoError(t, auth.Init(cfg))
}

func TestOAuthIntrospection_RegisteredInAuthLoader(t *testing.T) {
	fn, ok := authLoaderFuns[AuthTypeOAuthIntrospection]
	if !ok {
		t.Fatal("oauth_introspection auth type not registered in authLoaderFuns")
	}
	assert.NotNil(t, fn)
}

func TestOAuthIntrospection_ActiveTokenPassesThrough(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active":    true,
			"sub":       "user-123",
			"client_id": "test-client",
			"scope":     "read write",
			"username":  "testuser",
			"aud":       "my-api",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		assert.Equal(t, "user-123", r.Header.Get("X-Auth-Subject"))
		assert.Equal(t, "test-client", r.Header.Get("X-Auth-Client-ID"))
		assert.Equal(t, "read write", r.Header.Get("X-Auth-Scopes"))
		assert.Equal(t, "testuser", r.Header.Get("X-Auth-Username"))
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer valid-token-123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestOAuthIntrospection_InactiveTokenReturns401(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active": false,
		})
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for inactive token")
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer inactive-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "not active")
}

func TestOAuthIntrospection_MissingAuthorizationHeaderReturns401(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("introspection should not be called without a token")
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called without a token")
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Bearer token required")
}

func TestOAuthIntrospection_RequiredScopesValidated(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"scope":  "read",
			"sub":    "user-1",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, map[string]any{
		"required_scopes": []string{"read", "write"},
	}))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called when scopes are insufficient")
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer scoped-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Insufficient scope")
}

func TestOAuthIntrospection_RequiredScopesAllPresent(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"scope":  "read write admin",
			"sub":    "user-1",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, map[string]any{
		"required_scopes": []string{"read", "write"},
	}))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer full-scope-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestOAuthIntrospection_RequiredAudienceValidated(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-1",
			"aud":    "other-api",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, map[string]any{
		"required_audience": "my-api",
	}))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called with wrong audience")
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer aud-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid audience")
}

func TestOAuthIntrospection_CacheHitAvoidsIntrospectionCall(t *testing.T) {
	callCount := 0
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-1",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, map[string]any{
		"cache_duration": "60s",
	}))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)

	// First request - should call introspection
	req1 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req1.Header.Set("Authorization", "Bearer cached-token")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)
	assert.Equal(t, 1, callCount)

	// Second request with same token - should use cache
	req2 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req2.Header.Set("Authorization", "Bearer cached-token")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusOK, rr2.Code)
	assert.Equal(t, 1, callCount, "introspection should not be called again due to cache")
}

func TestOAuthIntrospection_IntrospectionEndpointErrorReturns401(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal error")
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called on introspection error")
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer error-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "introspection failed")
}

func TestOAuthIntrospection_ExpiredTokenReturns401(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-1",
			"exp":    time.Now().Add(-1 * time.Hour).Unix(), // expired 1 hour ago
		})
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for expired token")
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired")
}

func TestOAuthIntrospection_BasicAuthSentToIntrospectionEndpoint(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "test-client" || password != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Verify content type
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		// Verify token is sent in form body
		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "my-bearer-token", r.FormValue("token"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-1",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer my-bearer-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestOAuthIntrospection_CustomTokenHeader(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-1",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthIntrospectionConfig(introspectionConfigJSON(srv.URL, map[string]any{
		"token_header_name":   "X-API-Token",
		"token_header_prefix": "Token ",
	}))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)

	// Request with standard Authorization header should fail (wrong header)
	req1 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req1.Header.Set("Authorization", "Bearer some-token")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusUnauthorized, rr1.Code)

	// Request with custom header should succeed
	req2 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req2.Header.Set("X-API-Token", "Token my-custom-token")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr2.Code)
}

func TestOAuthIntrospection_LoadViaAuthLoader(t *testing.T) {
	srv := newIntrospectionServer(t, func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()

	data := introspectionConfigJSON(srv.URL, nil)
	auth, err := LoadAuthConfig(data)
	require.NoError(t, err)
	assert.Equal(t, AuthTypeOAuthIntrospection, auth.GetType())
}
