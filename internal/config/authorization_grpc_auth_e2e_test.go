package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestGRPCAuth_FullPipeline_E2E tests the gRPC external auth flow end-to-end
// through the auth configuration, request handling, and backend proxying pipeline.
func TestGRPCAuth_FullPipeline_E2E(t *testing.T) {
	t.Run("allowed request reaches backend", func(t *testing.T) {
		var backendCalled atomic.Int32

		// Mock backend server that the proxy forwards to after successful auth.
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendCalled.Add(1)
			// Verify trust headers were propagated from the auth server response.
			if got := r.Header.Get("X-Auth-User"); got != "user-42" {
				t.Errorf("expected X-Auth-User=user-42, got %q", got)
			}
			if got := r.Header.Get("X-Auth-Role"); got != "admin" {
				t.Errorf("expected X-Auth-Role=admin, got %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}))
		defer backend.Close()

		// Mock gRPC auth server that always allows requests.
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertGRPCAuthCheckRequest(t, r)

			resp := checkResponse{
				Status: &checkStatus{Code: 0},
				OKResponse: &checkOKResponse{
					Headers: []checkHeader{
						{Header: &checkHeaderKV{Key: "X-Auth-User", Value: "user-42"}},
						{Header: &checkHeaderKV{Key: "X-Auth-Role", Value: "admin"}},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer authServer.Close()

		authAddress := authServer.Listener.Addr().String()
		auth := setupGRPCAuth(t, authAddress, []string{"X-Auth-User", "X-Auth-Role"}, false)

		// Build the full handler chain: auth middleware wrapping the backend handler.
		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate forwarding to backend by checking headers and writing response.
			if got := r.Header.Get("X-Auth-User"); got != "user-42" {
				t.Errorf("backend: expected X-Auth-User=user-42, got %q", got)
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"proxied":true}`)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Authorization", "Bearer test-token-abc")
		req.Header.Set("X-Request-Id", "req-001")
		req.Host = "api.example.com"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("denied request returns 403 with body", func(t *testing.T) {
		// Mock gRPC auth server that denies requests.
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertGRPCAuthCheckRequest(t, r)

			resp := checkResponse{
				Status: &checkStatus{Code: 7}, // PERMISSION_DENIED
				DeniedResponse: &checkDeniedResponse{
					Status: &checkDeniedStatus{Code: http.StatusForbidden},
					Body:   "Access denied: insufficient permissions",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer authServer.Close()

		authAddress := authServer.Listener.Addr().String()
		auth := setupGRPCAuth(t, authAddress, nil, false)

		nextCalled := false
		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/secret", nil)
		req.Header.Set("Authorization", "Bearer bad-token")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if nextCalled {
			t.Error("backend handler should not have been called for denied request")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
		if got := rec.Body.String(); got != "Access denied: insufficient permissions" {
			t.Errorf("unexpected body: %q", got)
		}
	})

	t.Run("auth server toggle between allow and deny", func(t *testing.T) {
		// Auth server that toggles between allow and deny based on request count.
		var requestCount atomic.Int32

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := requestCount.Add(1)
			w.Header().Set("Content-Type", "application/json")

			if count%2 == 1 {
				// Odd requests: allow
				json.NewEncoder(w).Encode(checkResponse{
					Status: &checkStatus{Code: 0},
					OKResponse: &checkOKResponse{
						Headers: []checkHeader{
							{Header: &checkHeaderKV{Key: "X-Auth-User", Value: fmt.Sprintf("user-%d", count)}},
						},
					},
				})
			} else {
				// Even requests: deny
				json.NewEncoder(w).Encode(checkResponse{
					Status: &checkStatus{Code: 7},
					DeniedResponse: &checkDeniedResponse{
						Status: &checkDeniedStatus{Code: http.StatusForbidden},
						Body:   "denied",
					},
				})
			}
		}))
		defer authServer.Close()

		authAddress := authServer.Listener.Addr().String()
		auth := setupGRPCAuth(t, authAddress, []string{"X-Auth-User"}, false)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		handler := auth.Authenticate(next)

		// First request: should be allowed.
		req1 := httptest.NewRequest(http.MethodGet, "/api/toggle", nil)
		rec1 := httptest.NewRecorder()
		handler.ServeHTTP(rec1, req1)
		if rec1.Code != http.StatusOK {
			t.Errorf("request 1: expected 200, got %d", rec1.Code)
		}

		// Second request: should be denied.
		req2 := httptest.NewRequest(http.MethodGet, "/api/toggle", nil)
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusForbidden {
			t.Errorf("request 2: expected 403, got %d", rec2.Code)
		}

		// Third request: should be allowed again.
		req3 := httptest.NewRequest(http.MethodGet, "/api/toggle", nil)
		rec3 := httptest.NewRecorder()
		handler.ServeHTTP(rec3, req3)
		if rec3.Code != http.StatusOK {
			t.Errorf("request 3: expected 200, got %d", rec3.Code)
		}
	})

	t.Run("fail_open allows request when auth server is unreachable", func(t *testing.T) {
		auth := setupGRPCAuth(t, "127.0.0.1:1", nil, true)

		nextCalled := false
		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/fallback", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Error("expected backend to be called when fail_open is true and auth server is down")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("fail_closed blocks request when auth server is unreachable", func(t *testing.T) {
		auth := setupGRPCAuth(t, "127.0.0.1:1", nil, false)

		nextCalled := false
		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/fallback", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if nextCalled {
			t.Error("expected backend NOT to be called when fail_open is false and auth server is down")
		}
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", rec.Code)
		}
	})

	t.Run("request attributes forwarded to auth server", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req checkRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("failed to decode check request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			httpAttrs := req.Attributes.Request.HTTP
			if httpAttrs.Method != "POST" {
				t.Errorf("expected method POST, got %s", httpAttrs.Method)
			}
			if httpAttrs.Path != "/api/submit" {
				t.Errorf("expected path /api/submit, got %s", httpAttrs.Path)
			}
			if httpAttrs.Host != "myapp.example.com" {
				t.Errorf("expected host myapp.example.com, got %s", httpAttrs.Host)
			}
			if httpAttrs.Headers["content-type"] != "application/json" {
				t.Errorf("expected content-type header, got %q", httpAttrs.Headers["content-type"])
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(checkResponse{
				Status: &checkStatus{Code: 0},
			})
		}))
		defer authServer.Close()

		authAddress := authServer.Listener.Addr().String()
		auth := setupGRPCAuth(t, authAddress, nil, false)

		handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/submit", nil)
		req.Host = "myapp.example.com"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer xyz")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})
}

// setupGRPCAuth creates and initializes a GRPCAuthImpl for testing.
func setupGRPCAuth(t *testing.T, address string, trustHeaders []string, failOpen bool) AuthConfig {
	t.Helper()

	cfg := map[string]any{
		"type":      "grpc_auth",
		"address":   address,
		"fail_open": failOpen,
		"timeout":   "2s",
	}
	if len(trustHeaders) > 0 {
		cfg["trust_headers"] = trustHeaders
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	auth, err := NewGRPCAuthConfig(data)
	if err != nil {
		t.Fatalf("failed to create grpc_auth config: %v", err)
	}

	if err := auth.Init(&Config{ID: "grpc-auth-e2e-test"}); err != nil {
		t.Fatalf("failed to init auth: %v", err)
	}

	return auth
}

// assertGRPCAuthCheckRequest validates that the auth server received a properly
// formatted ext_authz check request.
func assertGRPCAuthCheckRequest(t *testing.T, r *http.Request) {
	t.Helper()

	if r.Method != http.MethodPost {
		t.Errorf("auth server: expected POST, got %s", r.Method)
	}
	if r.URL.Path != "/envoy.service.auth.v3.Authorization/Check" {
		t.Errorf("auth server: expected ext_authz path, got %s", r.URL.Path)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("auth server: expected Content-Type application/json, got %q", ct)
	}
}
