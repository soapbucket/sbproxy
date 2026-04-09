package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkGRPCAuth_Allow(b *testing.B) {
	b.ReportAllocs()
	// Create mock auth server that returns OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": map[string]any{"code": 0},
			"ok_response": map[string]any{
				"headers": []map[string]string{},
			},
		})
	}))
	defer server.Close()

	data, _ := json.Marshal(map[string]any{
		"type":    "grpc_auth",
		"address": server.URL,
		"timeout": "5s",
	})
	auth, err := NewGRPCAuthConfig(data)
	if err != nil {
		b.Fatalf("failed to create config: %v", err)
	}

	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer token123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkGRPCAuth_BuildCheckRequest(b *testing.B) {
	b.ReportAllocs()
	// Benchmark the full request path including request building overhead
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": map[string]any{"code": 0},
		})
	}))
	defer server.Close()

	data, _ := json.Marshal(map[string]any{
		"type":    "grpc_auth",
		"address": server.URL,
	})
	auth, err := NewGRPCAuthConfig(data)
	if err != nil {
		b.Fatalf("failed to create config: %v", err)
	}

	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v2/users?page=1", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("X-Request-ID", "req-abc-123")
	req.Header.Set("Accept", "application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}
