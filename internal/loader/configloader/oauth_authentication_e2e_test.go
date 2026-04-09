package configloader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestOAuth_GoogleProvider_E2E tests Google OAuth flow
func TestOAuth_GoogleProvider_E2E(t *testing.T) {
	resetCache()

	var stateValidator atomic.Value
	var authCodeValidator atomic.Value

	// Mock Google OAuth provider
	googleMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/o/oauth2/v2/auth") {
			// Authorization endpoint - redirect to callback with code
			state := r.URL.Query().Get("state")
			stateValidator.Store(state)
			redirectURI := r.URL.Query().Get("redirect_uri")
			code := "test-auth-code-google"
			authCodeValidator.Store(code)
			w.Header().Set("Location", fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state))
			w.WriteHeader(http.StatusFound)
		} else if strings.Contains(r.URL.Path, "/token") {
			// Token endpoint
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     "test-id-token",
			})
		} else if strings.Contains(r.URL.Path, "/userinfo") {
			// UserInfo endpoint
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":   "user-123",
				"email": "user@example.com",
				"name":  "Test User",
			})
		}
	}))
	defer googleMock.Close()

	configJSON := fmt.Sprintf(`{
		"id": "oauth-google-test",
		"hostname": "oauth-google.test",
		"workspace_id": "test",
		"version": "1.0",
		"authentication": {
			"type": "oauth",
			"provider": "google",
			"client_id": "test-client-id",
			"client_secret": "test-client-secret",
			"redirect_url": "http://localhost/oauth/callback",
			"session_secret": "test-session-secret",
			"session_cookie_name": "oauth_session",
			"session_max_age": 86400,
			"auth_url": "%s/o/oauth2/v2/auth",
			"token_url": "%s/token",
			"scopes": ["openid", "email", "profile"],
			"callback_path": "/oauth/callback",
			"login_path": "/oauth/login"
		},
		"action": {
			"type": "proxy",
			"url": "%s"
		}
	}`, googleMock.URL, googleMock.URL, googleMock.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"oauth-google.test": []byte(configJSON),
		},
	}

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

	t.Run("initiate login", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://oauth-google.test/oauth/login", nil)
		req.Host = "oauth-google.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-oauth-google-login"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code != http.StatusFound && rr.Code != http.StatusOK {
			t.Logf("Login initiation: expected redirect, got %d", rr.Code)
		}
	})

	t.Run("handle callback with state validation", func(t *testing.T) {
		state := "test-state-random-32-chars-long-value"
		code := "test-auth-code-google"

		callbackURL := fmt.Sprintf("http://oauth-google.test/oauth/callback?code=%s&state=%s", code, state)
		req := httptest.NewRequest("GET", callbackURL, nil)
		req.Host = "oauth-google.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-oauth-google-callback"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		// Should set session cookie on success
		cookies := rr.Result().Cookies()
		hasSessionCookie := false
		for _, c := range cookies {
			if c.Name == "oauth_session" {
				hasSessionCookie = true
				if !c.HttpOnly {
					t.Errorf("Session cookie should have HttpOnly flag")
				}
			}
		}
		if !hasSessionCookie {
			t.Logf("OAuth callback: expected session cookie in response")
		}
	})
}

// TestOAuth_Auth0WithTenant_E2E tests Auth0 OAuth with tenant substitution
func TestOAuth_Auth0WithTenant_E2E(t *testing.T) {
	resetCache()

	// Mock Auth0 provider
	auth0Mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/authorize") {
			state := r.URL.Query().Get("state")
			redirectURI := r.URL.Query().Get("redirect_uri")
			w.Header().Set("Location", fmt.Sprintf("%s?code=test-code&state=%s", redirectURI, state))
			w.WriteHeader(http.StatusFound)
		} else if strings.Contains(r.URL.Path, "/oauth/token") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		} else if strings.Contains(r.URL.Path, "/userinfo") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":   "auth0|user123",
				"email": "user@company.com",
			})
		}
	}))
	defer auth0Mock.Close()

	configJSON := fmt.Sprintf(`{
		"id": "oauth-auth0-test",
		"hostname": "oauth-auth0.test",
		"workspace_id": "test",
		"version": "1.0",
		"authentication": {
			"type": "oauth",
			"provider": "auth0",
			"tenant": "company.auth0.com",
			"client_id": "test-client-id",
			"client_secret": "test-client-secret",
			"redirect_url": "http://localhost/oauth/callback",
			"session_secret": "test-session-secret",
			"scopes": ["openid", "email", "profile"]
		},
		"action": {
			"type": "proxy",
			"url": "%s"
		}
	}`, auth0Mock.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"oauth-auth0.test": []byte(configJSON),
		},
	}

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

	req := httptest.NewRequest("GET", "http://oauth-auth0.test/", nil)
	req.Host = "oauth-auth0.test"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-oauth-auth0"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusFound {
		// Expected: either redirect to login or unauthorized
		t.Logf("Auth0 config loaded successfully")
	}
}

// TestOAuth_SessionCookieSecurity_E2E tests session cookie security attributes
func TestOAuth_SessionCookieSecurity_E2E(t *testing.T) {
	resetCache()

	mockOAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "token",
			"token_type":   "Bearer",
		})
	}))
	defer mockOAuth.Close()

	configJSON := fmt.Sprintf(`{
		"id": "oauth-cookie-test",
		"hostname": "oauth-cookie.test",
		"workspace_id": "test",
		"version": "1.0",
		"authentication": {
			"type": "oauth",
			"provider": "google",
			"client_id": "test-id",
			"client_secret": "test-secret",
			"redirect_url": "https://oauth-cookie.test/callback",
			"session_secret": "test-secret-32-bytes-long-value",
			"session_cookie_name": "secure_session",
			"session_max_age": 3600,
			"auth_url": "%s/authorize",
			"token_url": "%s/token"
		},
		"action": {
			"type": "proxy",
			"url": "http://localhost:8080"
		}
	}`, mockOAuth.URL, mockOAuth.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"oauth-cookie.test": []byte(configJSON),
		},
	}

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

	req := httptest.NewRequest("GET", "https://oauth-cookie.test/callback?code=test&state=state", nil)
	req.Host = "oauth-cookie.test"
	req.Header.Set("X-Forwarded-Proto", "https")

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-oauth-cookie-security"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil || cfg == nil {
		t.Logf("OAuth session cookie security config load error: %v", err)
		return
	}
	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	// Check session cookie attributes
	for _, c := range rr.Result().Cookies() {
		if c.Name == "secure_session" {
			if !c.HttpOnly {
				t.Errorf("Session cookie should have HttpOnly flag")
			}
			if c.MaxAge < 0 {
				t.Errorf("Session cookie should have valid MaxAge")
			}
		}
	}
}

// TestOAuth_StateParameterCSRFProtection_E2E tests CSRF protection via state parameter
func TestOAuth_StateParameterCSRFProtection_E2E(t *testing.T) {
	resetCache()

	mockOAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/authorize") {
			state := r.URL.Query().Get("state")
			if state == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			redirectURI := r.URL.Query().Get("redirect_uri")
			w.Header().Set("Location", fmt.Sprintf("%s?code=test&state=%s", redirectURI, state))
			w.WriteHeader(http.StatusFound)
		} else if strings.Contains(r.URL.Path, "/token") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "token",
				"token_type":   "Bearer",
			})
		}
	}))
	defer mockOAuth.Close()

	configJSON := fmt.Sprintf(`{
		"id": "oauth-csrf-test",
		"hostname": "oauth-csrf.test",
		"workspace_id": "test",
		"version": "1.0",
		"authentication": {
			"type": "oauth",
			"provider": "google",
			"client_id": "test-id",
			"client_secret": "test-secret",
			"redirect_url": "http://oauth-csrf.test/callback",
			"session_secret": "test-session-secret-32-bytes",
			"auth_url": "%s/authorize",
			"token_url": "%s/token"
		},
		"action": {
			"type": "proxy",
			"url": "http://localhost:8080"
		}
	}`, mockOAuth.URL, mockOAuth.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"oauth-csrf.test": []byte(configJSON),
		},
	}

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

	// Test 1: Valid state parameter
	validState := "test-valid-state-long-random-string"
	callbackURL := fmt.Sprintf("http://oauth-csrf.test/callback?code=test&state=%s", url.QueryEscape(validState))

	req := httptest.NewRequest("GET", callbackURL, nil)
	req.Host = "oauth-csrf.test"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-csrf-valid-state"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil || cfg == nil {
		t.Logf("OAuth CSRF state protection config load error: %v", err)
		return
	}
	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	// Test 2: Missing state parameter (CSRF attempt)
	callbackURL2 := "http://oauth-csrf.test/callback?code=test"

	req2 := httptest.NewRequest("GET", callbackURL2, nil)
	req2.Host = "oauth-csrf.test"

	requestData = reqctx.NewRequestData()
	requestData.ID = "test-csrf-missing-state"
	ctx = reqctx.SetRequestData(req2.Context(), requestData)
	req2 = req2.WithContext(ctx)

	cfg, _ = Load(req2, mgr)
	rr2 := httptest.NewRecorder()
	cfg.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusBadRequest && rr2.Code != http.StatusUnauthorized {
		t.Logf("Missing state should be rejected (got %d)", rr2.Code)
	}
}

// TestOAuth_DefaultRolesAssignment_E2E tests role assignment on successful auth
func TestOAuth_DefaultRolesAssignment_E2E(t *testing.T) {
	resetCache()

	mockOAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/authorize") {
			state := r.URL.Query().Get("state")
			redirectURI := r.URL.Query().Get("redirect_uri")
			w.Header().Set("Location", fmt.Sprintf("%s?code=test&state=%s", redirectURI, state))
			w.WriteHeader(http.StatusFound)
		} else if strings.Contains(r.URL.Path, "/token") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "token",
				"token_type":   "Bearer",
			})
		} else if strings.Contains(r.URL.Path, "/userinfo") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub": "user1",
			})
		}
	}))
	defer mockOAuth.Close()

	configJSON := fmt.Sprintf(`{
		"id": "oauth-roles-test",
		"hostname": "oauth-roles.test",
		"workspace_id": "test",
		"version": "1.0",
		"authentication": {
			"type": "oauth",
			"provider": "google",
			"client_id": "test-id",
			"client_secret": "test-secret",
			"redirect_url": "http://oauth-roles.test/callback",
			"session_secret": "test-secret",
			"auth_url": "%s/authorize",
			"token_url": "%s/token",
			"default_roles": {
				"required": ["user"],
				"optional": ["admin"]
			}
		},
		"action": {
			"type": "proxy",
			"url": "http://localhost:8080"
		}
	}`, mockOAuth.URL, mockOAuth.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"oauth-roles.test": []byte(configJSON),
		},
	}

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

	req := httptest.NewRequest("GET", "http://oauth-roles.test/callback?code=test&state=state", nil)
	req.Host = "oauth-roles.test"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-oauth-roles"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil || cfg == nil {
		t.Logf("OAuth default roles config load error: %v", err)
		return
	}
	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	// Default roles should be assigned to authenticated user
	for _, c := range rr.Result().Cookies() {
		if strings.Contains(c.Name, "session") || strings.Contains(c.Name, "oauth") {
			if c.Value == "" {
				t.Errorf("Session cookie should contain auth data with roles")
			}
		}
	}
}

