package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkOAuthClientCredentials_CachedToken(b *testing.B) {
	b.ReportAllocs()

	// Mock token server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cached-token-abc123",
			"token_type":   "bearer",
			"expires_in":   3600,
			"scope":        "read write",
		})
	}))
	defer server.Close()

	data, _ := json.Marshal(map[string]any{
		"type":      "oauth_client_credentials",
		"token_url": server.URL + "/token",
	})
	auth, err := NewOAuthClientCredentialsConfig(data)
	if err != nil {
		b.Fatalf("failed to create config: %v", err)
	}

	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make one initial call to populate the cache
	warmupReq := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	warmupReq.SetBasicAuth("client-id", "client-secret")
	warmupW := httptest.NewRecorder()
	handler.ServeHTTP(warmupW, warmupReq)
	if warmupW.Code != http.StatusOK {
		b.Fatalf("warmup request failed with status %d", warmupW.Code)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.SetBasicAuth("client-id", "client-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkOAuthClientCredentials_TokenExchange(b *testing.B) {
	b.ReportAllocs()

	// Mock token server that returns a new token each time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fresh-token-xyz789",
			"token_type":   "bearer",
			"expires_in":   3600,
			"scope":        "read write",
		})
	}))
	defer server.Close()

	data, _ := json.Marshal(map[string]any{
		"type":      "oauth_client_credentials",
		"token_url": server.URL + "/token",
	})
	auth, err := NewOAuthClientCredentialsConfig(data)
	if err != nil {
		b.Fatalf("failed to create config: %v", err)
	}

	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use a unique client ID each iteration to bypass the cache
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.SetBasicAuth("client-id", "client-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}
