package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// benchRoundTripper returns a fixed response for upstream requests in benchmarks.
type benchRoundTripper struct{}

func (m *benchRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	return rec.Result(), nil
}

func BenchmarkUpstreamOAuth_CachedToken(b *testing.B) {
	b.ReportAllocs()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cached-upstream-token",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	oauth := NewUpstreamOAuth(UpstreamOAuthConfig{
		TokenURL:     tokenServer.URL + "/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"api.read"},
	}, &benchRoundTripper{})

	// Prime the cache with one request
	warmupReq := httptest.NewRequest(http.MethodGet, "http://upstream.example.com/api", nil)
	if _, err := oauth.RoundTrip(warmupReq); err != nil {
		b.Fatalf("warmup request failed: %v", err)
	}

	// Verify the token is cached
	oauth.mu.RLock()
	if oauth.cachedToken == "" || time.Now().After(oauth.tokenExpiry) {
		oauth.mu.RUnlock()
		b.Fatal("token was not cached after warmup")
	}
	oauth.mu.RUnlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://upstream.example.com/api", nil)
		_, err := oauth.RoundTrip(req)
		if err != nil {
			b.Fatalf("RoundTrip failed: %v", err)
		}
	}
}

func BenchmarkUpstreamOAuth_TokenRefresh(b *testing.B) {
	b.ReportAllocs()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fresh-upstream-token",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	oauth := NewUpstreamOAuth(UpstreamOAuthConfig{
		TokenURL:     tokenServer.URL + "/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}, &benchRoundTripper{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Force token expiry before each iteration to trigger a refresh
		oauth.mu.Lock()
		oauth.cachedToken = ""
		oauth.tokenExpiry = time.Time{}
		oauth.mu.Unlock()

		req := httptest.NewRequest(http.MethodGet, "http://upstream.example.com/api", nil)
		_, err := oauth.RoundTrip(req)
		if err != nil {
			b.Fatalf("RoundTrip failed: %v", err)
		}
	}
}
