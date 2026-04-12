package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// roundTripFunc is a mock RoundTripper that captures the outgoing request.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// newMockTokenServer creates a test server that returns OAuth2 token responses.
func newMockTokenServer(t *testing.T, token string, expiresIn int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %s", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("expected grant_type=client_credentials, got %s", r.FormValue("grant_type"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: token,
			ExpiresIn:   expiresIn,
			TokenType:   "bearer",
		})
	}))
}

func TestUpstreamOAuth_InjectsToken(t *testing.T) {
	ts := newMockTokenServer(t, "test-token-abc", 3600)
	defer ts.Close()

	var capturedHeader string
	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedHeader = req.Header.Get("Authorization")
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	oauth := NewUpstreamOAuth(UpstreamOAuthConfig{
		TokenURL:     ts.URL,
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		Scopes:       []string{"read", "write"},
	}, mock)

	req, _ := http.NewRequest("GET", "http://backend.local/api/data", nil)
	resp, err := oauth.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if capturedHeader != "Bearer test-token-abc" {
		t.Errorf("expected Authorization header 'Bearer test-token-abc', got %q", capturedHeader)
	}
}

func TestUpstreamOAuth_CachesToken(t *testing.T) {
	var fetchCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "cached-token",
			ExpiresIn:   3600,
			TokenType:   "bearer",
		})
	}))
	defer ts.Close()

	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	oauth := NewUpstreamOAuth(UpstreamOAuthConfig{
		TokenURL:     ts.URL,
		ClientID:     "client",
		ClientSecret: "secret",
	}, mock)

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "http://backend.local/api", nil)
		resp, err := oauth.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	if count := fetchCount.Load(); count != 1 {
		t.Errorf("expected 1 token fetch, got %d", count)
	}
}

func TestUpstreamOAuth_RefreshesExpiredToken(t *testing.T) {
	var fetchCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(oauthTokenResponse{
			AccessToken: "refreshed-token",
			ExpiresIn:   3600,
			TokenType:   "bearer",
		})
	}))
	defer ts.Close()

	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})

	oauth := NewUpstreamOAuth(UpstreamOAuthConfig{
		TokenURL:     ts.URL,
		ClientID:     "client",
		ClientSecret: "secret",
	}, mock)

	// First request fetches a token.
	req, _ := http.NewRequest("GET", "http://backend.local/api", nil)
	resp, err := oauth.RoundTrip(req)
	if err != nil {
		t.Fatalf("first RoundTrip failed: %v", err)
	}
	resp.Body.Close()

	if count := fetchCount.Load(); count != 1 {
		t.Fatalf("expected 1 fetch after first request, got %d", count)
	}

	// Simulate token expiry by setting the expiry to the past.
	oauth.mu.Lock()
	oauth.tokenExpiry = time.Now().Add(-1 * time.Second)
	oauth.mu.Unlock()

	// Second request should trigger a re-fetch.
	req, _ = http.NewRequest("GET", "http://backend.local/api", nil)
	resp, err = oauth.RoundTrip(req)
	if err != nil {
		t.Fatalf("second RoundTrip failed: %v", err)
	}
	resp.Body.Close()

	if count := fetchCount.Load(); count != 2 {
		t.Errorf("expected 2 fetches after expired token, got %d", count)
	}
}

func TestUpstreamOAuth_TokenEndpointError(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			name: "500 status",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("internal error"))
			}),
			wantErr: "token endpoint returned 500",
		},
		{
			name: "invalid json",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte("not json"))
			}),
			wantErr: "parsing token response",
		},
		{
			name: "empty access token",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(oauthTokenResponse{
					AccessToken: "",
					ExpiresIn:   3600,
					TokenType:   "bearer",
				})
			}),
			wantErr: "empty access_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(tt.handler)
			defer ts.Close()

			mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				t.Fatal("transport should not be called on token error")
				return nil, nil
			})

			oauth := NewUpstreamOAuth(UpstreamOAuthConfig{
				TokenURL:     ts.URL,
				ClientID:     "client",
				ClientSecret: "secret",
			}, mock)

			req, _ := http.NewRequest("GET", "http://backend.local/api", nil)
			_, err := oauth.RoundTrip(req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); !contains(got, tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, got)
			}
		})
	}
}

func TestUpstreamOAuth_CustomHeaderName(t *testing.T) {
	ts := newMockTokenServer(t, "custom-token", 3600)
	defer ts.Close()

	tests := []struct {
		name       string
		headerName string
		prefix     string
		wantKey    string
		wantVal    string
	}{
		{
			name:       "custom header and prefix",
			headerName: "X-Service-Auth",
			prefix:     "Token ",
			wantKey:    "X-Service-Auth",
			wantVal:    "Token custom-token",
		},
		{
			name:       "custom header with default prefix",
			headerName: "X-Api-Key",
			prefix:     "",
			wantKey:    "X-Api-Key",
			wantVal:    "Bearer custom-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedKey, capturedVal string
			mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				capturedKey = tt.wantKey
				capturedVal = req.Header.Get(tt.wantKey)
				return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
			})

			oauth := NewUpstreamOAuth(UpstreamOAuthConfig{
				TokenURL:     ts.URL,
				ClientID:     "client",
				ClientSecret: "secret",
				HeaderName:   tt.headerName,
				HeaderPrefix: tt.prefix,
			}, mock)

			req, _ := http.NewRequest("GET", "http://backend.local/api", nil)
			resp, err := oauth.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip failed: %v", err)
			}
			resp.Body.Close()

			if capturedKey != tt.wantKey {
				t.Errorf("expected header key %q, got %q", tt.wantKey, capturedKey)
			}
			if capturedVal != tt.wantVal {
				t.Errorf("expected header value %q, got %q", tt.wantVal, capturedVal)
			}
		})
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
