package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestOAuthClientCredentials_FullPipeline_E2E tests the OAuth 2.0 Client Credentials Grant
// flow end-to-end through the auth configuration, token exchange, and backend proxying pipeline.
func TestOAuthClientCredentials_FullPipeline_E2E(t *testing.T) {
	t.Run("valid credentials trigger token exchange and reach backend", func(t *testing.T) {
		var tokenServerCalled atomic.Int32

		// Mock OAuth token server.
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenServerCalled.Add(1)

			// Verify the token request format.
			if r.Method != http.MethodPost {
				t.Errorf("token server: expected POST, got %s", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
				t.Errorf("token server: expected form content-type, got %q", ct)
			}

			username, password, ok := r.BasicAuth()
			if !ok {
				t.Error("token server: expected Basic auth credentials")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if username != "my-client-id" || password != "my-client-secret" {
				t.Errorf("token server: unexpected credentials: %s/%s", username, password)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if err := r.ParseForm(); err != nil {
				t.Errorf("token server: failed to parse form: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if gt := r.FormValue("grant_type"); gt != "client_credentials" {
				t.Errorf("token server: expected grant_type=client_credentials, got %q", gt)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token-xyz",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "read write",
			})
		}))
		defer tokenServer.Close()

		// Mock backend server.
		var backendCalled atomic.Int32
		backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendCalled.Add(1)

			// Verify the upstream token was injected.
			if got := r.Header.Get("Authorization"); got != "Bearer access-token-xyz" {
				t.Errorf("backend: expected Authorization=Bearer access-token-xyz, got %q", got)
			}
			// Verify metadata headers.
			if got := r.Header.Get("X-Auth-Client-ID"); got != "my-client-id" {
				t.Errorf("backend: expected X-Auth-Client-ID=my-client-id, got %q", got)
			}
			if got := r.Header.Get("X-Auth-Scopes"); got != "read write" {
				t.Errorf("backend: expected X-Auth-Scopes=read write, got %q", got)
			}

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"result":"success"}`)
		})

		auth := setupClientCredentialsAuth(t, tokenServer.URL, nil)
		handler := auth.Authenticate(backend)

		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.SetBasicAuth("my-client-id", "my-client-secret")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
		if tokenServerCalled.Load() != 1 {
			t.Errorf("expected token server to be called once, got %d", tokenServerCalled.Load())
		}
		if backendCalled.Load() != 1 {
			t.Errorf("expected backend to be called once, got %d", backendCalled.Load())
		}
	})

	t.Run("invalid credentials return 401 without reaching backend", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Reject all credentials.
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
		}))
		defer tokenServer.Close()

		backendCalled := false
		backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendCalled = true
		})

		auth := setupClientCredentialsAuth(t, tokenServer.URL, nil)
		handler := auth.Authenticate(backend)

		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.SetBasicAuth("wrong-client", "wrong-secret")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if backendCalled {
			t.Error("backend should not be called for invalid credentials")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("missing credentials return 401", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("token server should not be called without credentials")
		}))
		defer tokenServer.Close()

		auth := setupClientCredentialsAuth(t, tokenServer.URL, nil)
		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("backend should not be called without credentials")
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		// No BasicAuth set.
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("token server receives requested scopes", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			scope := r.FormValue("scope")
			if scope != "read write admin" {
				t.Errorf("expected scope 'read write admin', got %q", scope)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "scoped-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "read write admin",
			})
		}))
		defer tokenServer.Close()

		auth := setupClientCredentialsAuth(t, tokenServer.URL, map[string]any{
			"scopes": []string{"read", "write", "admin"},
		})
		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.SetBasicAuth("client", "secret")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("insufficient scopes return 403", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "limited-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "read",
			})
		}))
		defer tokenServer.Close()

		auth := setupClientCredentialsAuth(t, tokenServer.URL, map[string]any{
			"required_scopes": []string{"read", "write"},
		})

		backendCalled := false
		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendCalled = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.SetBasicAuth("client", "secret")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if backendCalled {
			t.Error("backend should not be called when scopes are insufficient")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("token caching avoids repeated token exchanges", func(t *testing.T) {
		var tokenCalls atomic.Int32

		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "cached-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "read write",
			})
		}))
		defer tokenServer.Close()

		auth := setupClientCredentialsAuth(t, tokenServer.URL, map[string]any{
			"cache_duration": "60s",
		})

		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Send three requests with the same credentials.
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
			req.SetBasicAuth("cache-client", "cache-secret")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
			}
		}

		if calls := tokenCalls.Load(); calls != 1 {
			t.Errorf("expected token server to be called once (cached), got %d calls", calls)
		}
	})

	t.Run("custom header name and prefix", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "custom-header-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		}))
		defer tokenServer.Close()

		auth := setupClientCredentialsAuth(t, tokenServer.URL, map[string]any{
			"header_name":   "X-Upstream-Token",
			"header_prefix": "Token ",
		})

		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("X-Upstream-Token"); got != "Token custom-header-token" {
				t.Errorf("expected X-Upstream-Token=Token custom-header-token, got %q", got)
			}
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.SetBasicAuth("client", "secret")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})
}

// setupClientCredentialsAuth creates and initializes an OAuthClientCredentialsImpl for testing.
func setupClientCredentialsAuth(t *testing.T, tokenServerURL string, overrides map[string]any) AuthConfig {
	t.Helper()

	cfg := map[string]any{
		"type":      "oauth_client_credentials",
		"token_url": tokenServerURL + "/token",
	}
	for k, v := range overrides {
		cfg[k] = v
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	auth, err := NewOAuthClientCredentialsConfig(data)
	if err != nil {
		t.Fatalf("failed to create oauth_client_credentials config: %v", err)
	}

	if err := auth.Init(&Config{ID: "oauth-cc-e2e-test"}); err != nil {
		t.Fatalf("failed to init auth: %v", err)
	}

	return auth
}
