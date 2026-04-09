package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newClientCredentialsServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func clientCredentialsConfigJSON(serverURL string, overrides map[string]any) []byte {
	cfg := map[string]any{
		"type":      "oauth_client_credentials",
		"token_url": serverURL + "/token",
	}
	for k, v := range overrides {
		cfg[k] = v
	}
	data, _ := json.Marshal(cfg)
	return data
}

func TestNewOAuthClientCredentialsConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
		check   func(*testing.T, *OAuthClientCredentialsImpl)
	}{
		{
			name: "valid config with required fields",
			data: `{
				"type": "oauth_client_credentials",
				"token_url": "https://auth.example.com/token"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *OAuthClientCredentialsImpl) {
				assert.Equal(t, "https://auth.example.com/token", cfg.TokenURL)
				assert.Equal(t, DefaultClientCredentialsHeaderName, cfg.HeaderName)
				assert.Equal(t, DefaultClientCredentialsHeaderPrefix, cfg.HeaderPrefix)
			},
		},
		{
			name: "valid config with all options",
			data: `{
				"type": "oauth_client_credentials",
				"token_url": "https://auth.example.com/token",
				"scopes": ["read", "write"],
				"required_scopes": ["read"],
				"cache_duration": "120s",
				"timeout": "10s",
				"header_name": "X-Upstream-Token",
				"header_prefix": "Token "
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *OAuthClientCredentialsImpl) {
				assert.Equal(t, []string{"read", "write"}, cfg.Scopes)
				assert.Equal(t, []string{"read"}, cfg.RequiredScopes)
				assert.Equal(t, "X-Upstream-Token", cfg.HeaderName)
				assert.Equal(t, "Token ", cfg.HeaderPrefix)
			},
		},
		{
			name:    "missing token_url returns error",
			data:    `{"type": "oauth_client_credentials"}`,
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
			auth, err := NewOAuthClientCredentialsConfig([]byte(tt.data))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			cfg, ok := auth.(*OAuthClientCredentialsImpl)
			require.True(t, ok)
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestOAuthClientCredentials_RegisteredInAuthLoader(t *testing.T) {
	fn, ok := authLoaderFuns[AuthTypeOAuthClientCredentials]
	if !ok {
		t.Fatal("oauth_client_credentials auth type not registered in authLoaderFuns")
	}
	assert.NotNil(t, fn)
}

func TestOAuthClientCredentials_ValidCredentials(t *testing.T) {
	srv := newClientCredentialsServer(t, func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "test-client" || password != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "client_credentials", r.FormValue("grant_type"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read write",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthClientCredentialsConfig(clientCredentialsConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		assert.Equal(t, "Bearer new-access-token-123", r.Header.Get("Authorization"))
		assert.Equal(t, "test-client", r.Header.Get("X-Auth-Client-ID"))
		assert.Equal(t, "read write", r.Header.Get("X-Auth-Scopes"))
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.SetBasicAuth("test-client", "test-secret")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestOAuthClientCredentials_InvalidCredentials(t *testing.T) {
	srv := newClientCredentialsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error": "invalid_client"}`)
	})
	defer srv.Close()

	auth, err := NewOAuthClientCredentialsConfig(clientCredentialsConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for invalid credentials")
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.SetBasicAuth("bad-client", "bad-secret")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Token exchange failed")
}

func TestOAuthClientCredentials_MissingCredentials(t *testing.T) {
	srv := newClientCredentialsServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("token endpoint should not be called without credentials")
	})
	defer srv.Close()

	auth, err := NewOAuthClientCredentialsConfig(clientCredentialsConfigJSON(srv.URL, nil))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called without credentials")
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Basic auth credentials required")
}

func TestOAuthClientCredentials_ScopeValidation(t *testing.T) {
	srv := newClientCredentialsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "scoped-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthClientCredentialsConfig(clientCredentialsConfigJSON(srv.URL, map[string]any{
		"required_scopes": []string{"read", "write"},
	}))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called when scopes are insufficient")
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.SetBasicAuth("test-client", "test-secret")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Insufficient scope")
}

func TestOAuthClientCredentials_CachedToken(t *testing.T) {
	callCount := 0
	srv := newClientCredentialsServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cached-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read write",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthClientCredentialsConfig(clientCredentialsConfigJSON(srv.URL, map[string]any{
		"cache_duration": "60s",
	}))
	require.NoError(t, err)
	auth.Init(&Config{ID: "test"})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)

	// First request - should call token endpoint
	req1 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req1.SetBasicAuth("cache-client", "cache-secret")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)
	assert.Equal(t, 1, callCount)

	// Second request with same credentials - should use cache
	req2 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req2.SetBasicAuth("cache-client", "cache-secret")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusOK, rr2.Code)
	assert.Equal(t, 1, callCount, "token endpoint should not be called again due to cache")
}

func TestOAuthClientCredentials_LoadViaAuthLoader(t *testing.T) {
	srv := newClientCredentialsServer(t, func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()

	data := clientCredentialsConfigJSON(srv.URL, nil)
	auth, err := LoadAuthConfig(data)
	require.NoError(t, err)
	assert.Equal(t, AuthTypeOAuthClientCredentials, auth.GetType())
}

func TestOAuthClientCredentials_ScopesPassedToTokenEndpoint(t *testing.T) {
	srv := newClientCredentialsServer(t, func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "read write admin", r.FormValue("scope"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "scoped-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read write admin",
		})
	})
	defer srv.Close()

	auth, err := NewOAuthClientCredentialsConfig(clientCredentialsConfigJSON(srv.URL, map[string]any{
		"scopes": []string{"read", "write", "admin"},
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
	req.SetBasicAuth("test-client", "test-secret")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
}
