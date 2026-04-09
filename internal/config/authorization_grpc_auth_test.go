package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGRPCAuthConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
		check   func(*testing.T, *GRPCAuthImpl)
	}{
		{
			name: "valid config with address only",
			data: `{
				"type": "grpc_auth",
				"address": "auth.example.com:50051"
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *GRPCAuthImpl) {
				assert.Equal(t, "auth.example.com:50051", cfg.Address)
				assert.False(t, cfg.TLS)
				assert.False(t, cfg.FailOpen)
			},
		},
		{
			name: "valid config with all options",
			data: `{
				"type": "grpc_auth",
				"address": "auth.example.com:50051",
				"timeout": "10s",
				"tls": true,
				"fail_open": true,
				"trust_headers": ["X-User-Id", "X-User-Role"]
			}`,
			wantErr: false,
			check: func(t *testing.T, cfg *GRPCAuthImpl) {
				assert.Equal(t, "auth.example.com:50051", cfg.Address)
				assert.True(t, cfg.TLS)
				assert.True(t, cfg.FailOpen)
				assert.Equal(t, []string{"X-User-Id", "X-User-Role"}, cfg.TrustHeaders)
			},
		},
		{
			name:    "missing address returns error",
			data:    `{"type": "grpc_auth"}`,
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
			auth, err := NewGRPCAuthConfig([]byte(tt.data))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			cfg, ok := auth.(*GRPCAuthImpl)
			require.True(t, ok)
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestGRPCAuth_GetType(t *testing.T) {
	auth, err := NewGRPCAuthConfig([]byte(`{"type": "grpc_auth", "address": "localhost:50051"}`))
	require.NoError(t, err)
	assert.Equal(t, "grpc_auth", auth.GetType())
}

func TestGRPCAuth_Init(t *testing.T) {
	auth, err := NewGRPCAuthConfig([]byte(`{"type": "grpc_auth", "address": "localhost:50051"}`))
	require.NoError(t, err)
	cfg := &Config{ID: "test-origin"}
	require.NoError(t, auth.Init(cfg))
}

func TestGRPCAuth_Allow(t *testing.T) {
	// Mock auth server that returns OK (code 0)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/envoy.service.auth.v3.Authorization/Check", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		resp := checkResponse{
			Status: &checkStatus{Code: 0},
			OKResponse: &checkOKResponse{
				Headers: []checkHeader{
					{Header: &checkHeaderKV{Key: "X-Auth-User", Value: "user-42"}},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer authServer.Close()

	// Extract host:port from the test server URL (strip http://)
	address := authServer.Listener.Addr().String()

	data, _ := json.Marshal(map[string]any{
		"type":          "grpc_auth",
		"address":       address,
		"trust_headers": []string{"X-Auth-User"},
	})

	auth, err := NewGRPCAuthConfig(data)
	require.NoError(t, err)
	require.NoError(t, auth.Init(&Config{ID: "test"}))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, "user-42", r.Header.Get("X-Auth-User"))
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called, "next handler should have been called")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGRPCAuth_Deny(t *testing.T) {
	// Mock auth server that returns DENIED
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := checkResponse{
			Status: &checkStatus{Code: 7}, // PERMISSION_DENIED
			DeniedResponse: &checkDeniedResponse{
				Status: &checkDeniedStatus{Code: http.StatusForbidden},
				Body:   "Access denied by external auth",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer authServer.Close()

	address := authServer.Listener.Addr().String()

	data, _ := json.Marshal(map[string]any{
		"type":    "grpc_auth",
		"address": address,
	})

	auth, err := NewGRPCAuthConfig(data)
	require.NoError(t, err)
	require.NoError(t, auth.Init(&Config{ID: "test"}))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called, "next handler should not have been called")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "Access denied by external auth", rec.Body.String())
}

func TestGRPCAuth_FailOpen(t *testing.T) {
	// Use a URL that will fail to connect
	data, _ := json.Marshal(map[string]any{
		"type":      "grpc_auth",
		"address":   "127.0.0.1:1", // port 1 should refuse connections
		"fail_open": true,
		"timeout":   "1s",
	})

	auth, err := NewGRPCAuthConfig(data)
	require.NoError(t, err)
	require.NoError(t, auth.Init(&Config{ID: "test"}))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called, "next handler should have been called when fail_open is true")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGRPCAuth_FailClosed(t *testing.T) {
	// Use a URL that will fail to connect
	data, _ := json.Marshal(map[string]any{
		"type":      "grpc_auth",
		"address":   "127.0.0.1:1", // port 1 should refuse connections
		"fail_open": false,
		"timeout":   "1s",
	})

	auth, err := NewGRPCAuthConfig(data)
	require.NoError(t, err)
	require.NoError(t, auth.Init(&Config{ID: "test"}))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, called, "next handler should not have been called when fail_open is false")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestGRPCAuth_TrustHeaders(t *testing.T) {
	// Mock auth server that returns OK with multiple headers
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := checkResponse{
			Status: &checkStatus{Code: 0},
			OKResponse: &checkOKResponse{
				Headers: []checkHeader{
					{Header: &checkHeaderKV{Key: "X-User-Id", Value: "user-42"}},
					{Header: &checkHeaderKV{Key: "X-User-Role", Value: "admin"}},
					{Header: &checkHeaderKV{Key: "X-Internal-Debug", Value: "should-not-propagate"}},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer authServer.Close()

	address := authServer.Listener.Addr().String()

	data, _ := json.Marshal(map[string]any{
		"type":          "grpc_auth",
		"address":       address,
		"trust_headers": []string{"X-User-Id", "X-User-Role"},
	})

	auth, err := NewGRPCAuthConfig(data)
	require.NoError(t, err)
	require.NoError(t, auth.Init(&Config{ID: "test"}))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, "user-42", r.Header.Get("X-User-Id"))
		assert.Equal(t, "admin", r.Header.Get("X-User-Role"))
		assert.Empty(t, r.Header.Get("X-Internal-Debug"), "untrusted header should not be propagated")
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called, "next handler should have been called")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGRPCAuth_Registration(t *testing.T) {
	fn, ok := authLoaderFuns[AuthTypeGRPCAuth]
	if !ok {
		t.Fatal("grpc_auth type not registered in authLoaderFuns")
	}

	data := []byte(`{"type": "grpc_auth", "address": "localhost:50051"}`)
	auth, err := fn(data)
	require.NoError(t, err)
	assert.Equal(t, "grpc_auth", auth.GetType())
}

func TestGRPCAuth_LoadAuthConfig(t *testing.T) {
	data := []byte(`{"type": "grpc_auth", "address": "localhost:50051"}`)
	auth, err := LoadAuthConfig(data)
	require.NoError(t, err)
	assert.Equal(t, "grpc_auth", auth.GetType())
}

func TestGRPCAuth_CheckRequestFormat(t *testing.T) {
	// Verify the check request contains the correct HTTP attributes
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req checkRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		assert.NotNil(t, req.Attributes)
		assert.NotNil(t, req.Attributes.Request)
		assert.NotNil(t, req.Attributes.Request.HTTP)

		http := req.Attributes.Request.HTTP
		assert.Equal(t, "POST", http.Method)
		assert.Equal(t, "/api/data", http.Path)
		assert.Equal(t, "example.com", http.Host)
		assert.Equal(t, "Bearer my-token", http.Headers["authorization"])

		resp := checkResponse{
			Status: &checkStatus{Code: 0},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer authServer.Close()

	address := authServer.Listener.Addr().String()

	data, _ := json.Marshal(map[string]any{
		"type":    "grpc_auth",
		"address": address,
	})

	auth, err := NewGRPCAuthConfig(data)
	require.NoError(t, err)
	require.NoError(t, auth.Init(&Config{ID: "test"}))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.Authenticate(next)
	req := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	req.Host = "example.com"
	req.Header.Set("Authorization", "Bearer my-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
