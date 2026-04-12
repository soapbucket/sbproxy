package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

// testRSAKey generates a 2048-bit RSA key pair for testing.
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

// signJWT creates a valid RS256-signed JWT token for testing.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	hBytes, _ := json.Marshal(header)
	cBytes, _ := json.Marshal(claims)

	h := base64.RawURLEncoding.EncodeToString(hBytes)
	p := base64.RawURLEncoding.EncodeToString(cBytes)
	signingInput := h + "." + p

	hashed := crypto.SHA256.New()
	hashed.Write([]byte(signingInput))
	digest := hashed.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksServer starts an httptest.Server serving a JWKS containing the given
// public key. Returns the server (caller must close) and the URL.
func jwksServer(t *testing.T, key *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	jwk := map[string]string{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
	body, _ := json.Marshal(map[string]any{"keys": []any{jwk}})

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
}

func TestJWTAuthenticator(t *testing.T) {
	privKey := testRSAKey(t)
	kid := "test-key-1"
	srv := jwksServer(t, &privKey.PublicKey, kid)
	defer srv.Close()

	now := time.Now()

	tests := []struct {
		name      string
		policy    *JWTPolicy
		token     func() string
		wantErr   string
		wantSub   string
		wantEmail string
		wantGroups []string
		wantExtra  map[string]string
	}{
		{
			name: "valid token with all claims",
			policy: &JWTPolicy{
				WorkspaceID:  "ws1",
				JWKSURL:      srv.URL,
				Issuer:       "https://idp.example.com",
				Audience:     "my-api",
				GroupsClaim:  "roles",
				ClaimMapping: map[string]string{"department": "dept"},
				CacheTTL:     5 * time.Minute,
			},
			token: func() string {
				return signJWT(t, privKey, kid, map[string]any{
					"sub":        "user-123",
					"email":      "alice@example.com",
					"name":       "Alice",
					"iss":        "https://idp.example.com",
					"aud":        "my-api",
					"exp":        float64(now.Add(1 * time.Hour).Unix()),
					"iat":        float64(now.Unix()),
					"roles":      []string{"admin", "editor"},
					"department": "engineering",
				})
			},
			wantSub:    "user-123",
			wantEmail:  "alice@example.com",
			wantGroups: []string{"admin", "editor"},
			wantExtra:  map[string]string{"dept": "engineering"},
		},
		{
			name: "expired token",
			policy: &JWTPolicy{
				WorkspaceID: "ws1",
				JWKSURL:     srv.URL,
				CacheTTL:    5 * time.Minute,
			},
			token: func() string {
				return signJWT(t, privKey, kid, map[string]any{
					"sub": "user-123",
					"exp": float64(now.Add(-1 * time.Hour).Unix()),
				})
			},
			wantErr: "token expired",
		},
		{
			name: "wrong issuer",
			policy: &JWTPolicy{
				WorkspaceID: "ws1",
				JWKSURL:     srv.URL,
				Issuer:      "https://correct.example.com",
				CacheTTL:    5 * time.Minute,
			},
			token: func() string {
				return signJWT(t, privKey, kid, map[string]any{
					"sub": "user-123",
					"iss": "https://wrong.example.com",
					"exp": float64(now.Add(1 * time.Hour).Unix()),
				})
			},
			wantErr: "issuer mismatch",
		},
		{
			name: "wrong audience",
			policy: &JWTPolicy{
				WorkspaceID: "ws1",
				JWKSURL:     srv.URL,
				Audience:    "correct-api",
				CacheTTL:    5 * time.Minute,
			},
			token: func() string {
				return signJWT(t, privKey, kid, map[string]any{
					"sub": "user-123",
					"aud": "wrong-api",
					"exp": float64(now.Add(1 * time.Hour).Unix()),
				})
			},
			wantErr: "audience mismatch",
		},
		{
			name: "invalid signature",
			policy: &JWTPolicy{
				WorkspaceID: "ws1",
				JWKSURL:     srv.URL,
				CacheTTL:    5 * time.Minute,
			},
			token: func() string {
				// Sign with a different key.
				otherKey := testRSAKey(t)
				return signJWT(t, otherKey, kid, map[string]any{
					"sub": "user-123",
					"exp": float64(now.Add(1 * time.Hour).Unix()),
				})
			},
			wantErr: "invalid signature",
		},
		{
			name: "empty token",
			policy: &JWTPolicy{
				WorkspaceID: "ws1",
				JWKSURL:     srv.URL,
			},
			token:   func() string { return "" },
			wantErr: "empty token",
		},
		{
			name: "malformed token - too few parts",
			policy: &JWTPolicy{
				WorkspaceID: "ws1",
				JWKSURL:     srv.URL,
			},
			token:   func() string { return "only-one-part" },
			wantErr: "malformed token",
		},
		{
			name: "no matching kid in JWKS",
			policy: &JWTPolicy{
				WorkspaceID: "ws1",
				JWKSURL:     srv.URL,
				CacheTTL:    5 * time.Minute,
			},
			token: func() string {
				return signJWT(t, privKey, "unknown-kid", map[string]any{
					"sub": "user-123",
					"exp": float64(now.Add(1 * time.Hour).Unix()),
				})
			},
			wantErr: "no matching key",
		},
		{
			name: "token not yet valid (nbf in future)",
			policy: &JWTPolicy{
				WorkspaceID: "ws1",
				JWKSURL:     srv.URL,
				CacheTTL:    5 * time.Minute,
			},
			token: func() string {
				return signJWT(t, privKey, kid, map[string]any{
					"sub": "user-123",
					"exp": float64(now.Add(2 * time.Hour).Unix()),
					"nbf": float64(now.Add(1 * time.Hour).Unix()),
				})
			},
			wantErr: "not yet valid",
		},
		{
			name: "default groups claim",
			policy: &JWTPolicy{
				WorkspaceID: "ws1",
				JWKSURL:     srv.URL,
				CacheTTL:    5 * time.Minute,
			},
			token: func() string {
				return signJWT(t, privKey, kid, map[string]any{
					"sub":    "user-456",
					"exp":    float64(now.Add(1 * time.Hour).Unix()),
					"groups": []string{"readers"},
				})
			},
			wantSub:    "user-456",
			wantGroups: []string{"readers"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewJWTAuthenticator()
			auth.httpClient = srv.Client()
			auth.AddPolicy(tt.policy)

			claims, err := auth.Authenticate(context.Background(), tt.policy.WorkspaceID, tt.token())
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if got := err.Error(); !containsSubstring(got, tt.wantErr) {
					t.Fatalf("error %q does not contain %q", got, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if claims.Subject != tt.wantSub {
				t.Errorf("Subject: got %q, want %q", claims.Subject, tt.wantSub)
			}
			if claims.Email != tt.wantEmail {
				t.Errorf("Email: got %q, want %q", claims.Email, tt.wantEmail)
			}
			if len(claims.Groups) != len(tt.wantGroups) {
				t.Errorf("Groups: got %v, want %v", claims.Groups, tt.wantGroups)
			} else {
				for i := range claims.Groups {
					if claims.Groups[i] != tt.wantGroups[i] {
						t.Errorf("Groups[%d]: got %q, want %q", i, claims.Groups[i], tt.wantGroups[i])
					}
				}
			}
			if tt.wantExtra != nil {
				for k, v := range tt.wantExtra {
					if claims.Extra[k] != v {
						t.Errorf("Extra[%q]: got %q, want %q", k, claims.Extra[k], v)
					}
				}
			}
		})
	}
}

func TestJWTAuthenticator_NoPolicy(t *testing.T) {
	auth := NewJWTAuthenticator()
	_, err := auth.Authenticate(context.Background(), "nonexistent-ws", "some.token.here")
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
	if got := err.Error(); !containsSubstring(got, "no policy") {
		t.Errorf("error %q does not mention missing policy", got)
	}
}

func TestJWTAuthenticator_JWKSCaching(t *testing.T) {
	privKey := testRSAKey(t)
	kid := "cache-key"

	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		jwk := map[string]string{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.PublicKey.E)).Bytes()),
		}
		body, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	auth := NewJWTAuthenticator()
	auth.httpClient = srv.Client()
	auth.AddPolicy(&JWTPolicy{
		WorkspaceID: "ws1",
		JWKSURL:     srv.URL,
		CacheTTL:    10 * time.Minute,
	})

	now := time.Now()
	for i := 0; i < 5; i++ {
		token := signJWT(t, privKey, kid, map[string]any{
			"sub": fmt.Sprintf("user-%d", i),
			"exp": float64(now.Add(1 * time.Hour).Unix()),
		})
		_, err := auth.Authenticate(context.Background(), "ws1", token)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}

	if fetchCount != 1 {
		t.Errorf("JWKS fetched %d times, expected 1 (caching broken)", fetchCount)
	}
}

func TestJWTAuthenticator_JWKSFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	privKey := testRSAKey(t)
	auth := NewJWTAuthenticator()
	auth.httpClient = srv.Client()
	auth.AddPolicy(&JWTPolicy{
		WorkspaceID: "ws1",
		JWKSURL:     srv.URL,
		CacheTTL:    5 * time.Minute,
	})

	token := signJWT(t, privKey, "kid1", map[string]any{
		"sub": "user-1",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})
	_, err := auth.Authenticate(context.Background(), "ws1", token)
	if err == nil {
		t.Fatal("expected error for JWKS fetch failure")
	}
	if got := err.Error(); !containsSubstring(got, "status 500") {
		t.Errorf("error %q does not mention status 500", got)
	}
}

func TestJWTAuthenticator_UnsupportedAlgorithm(t *testing.T) {
	privKey := testRSAKey(t)
	kid := "test-key"
	srv := jwksServer(t, &privKey.PublicKey, kid)
	defer srv.Close()

	auth := NewJWTAuthenticator()
	auth.httpClient = srv.Client()
	auth.AddPolicy(&JWTPolicy{
		WorkspaceID: "ws1",
		JWKSURL:     srv.URL,
		CacheTTL:    5 * time.Minute,
	})

	// Manually create a token with HS256 header.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"test-key"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1"}`))
	token := header + "." + payload + ".fakesig"

	_, err := auth.Authenticate(context.Background(), "ws1", token)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if got := err.Error(); !containsSubstring(got, "unsupported algorithm") {
		t.Errorf("error %q does not mention unsupported algorithm", got)
	}
}

func TestAddPolicy_Nil(t *testing.T) {
	auth := NewJWTAuthenticator()
	auth.AddPolicy(nil) // should not panic
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
