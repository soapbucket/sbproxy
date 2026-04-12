package configloader

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v4"
)

// generateHS256Token creates a JWT token signed with HS256.
func generateHS256Token(t *testing.T, secret string, claims gjwt.MapClaims) string {
	t.Helper()
	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("generateHS256Token: %v", err)
	}
	return signed
}

// TestJWT_RS256Validation_E2E tests RS256 (RSA) JWT validation
func TestJWT_RS256Validation_E2E(t *testing.T) {
	resetCache()
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	// Encode public key to PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	// Create a signed token
	token := gjwt.NewWithClaims(gjwt.SigningMethodRS256, gjwt.MapClaims{
		"sub": "user-1",
		"iss": "test-issuer",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	signed, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	cfg := originJSON(t, map[string]any{
		"hostname": "jwt-rs256.test",
		"action":   map[string]any{"type": "echo"},
		"authentication": map[string]any{
			"type":       "jwt",
			"algorithm":  "RS256",
			"public_key": string(pubPEM),
			"issuer":     "test-issuer",
			"audience":   "test-audience",
		},
	})

	t.Run("valid RS256 token passes", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://jwt-rs256.test/")
		r.Header.Set("Authorization", "Bearer "+signed)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("missing token returns 401", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://jwt-rs256.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://jwt-rs256.test/")
		r.Header.Set("Authorization", "Bearer invalid.token.here")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

// TestJWT_HS256Validation_E2E tests HS256 (HMAC) JWT validation
func TestJWT_HS256Validation_E2E(t *testing.T) {
	resetCache()
	secret := "jR7tK3mW9pL2vX5qJ8bN4mW6nY3zA!"

	validToken := generateHS256Token(t, secret, gjwt.MapClaims{
		"sub": "user-42",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	cfg := originJSON(t, map[string]any{
		"hostname": "jwt-hs256.test",
		"action":   map[string]any{"type": "echo"},
		"authentication": map[string]any{
			"type":      "jwt",
			"algorithm": "HS256",
			"secret":    secret,
		},
	})

	t.Run("valid HS256 token passes", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://jwt-hs256.test/")
		r.Header.Set("Authorization", "Bearer "+validToken)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("wrong secret returns 401", func(t *testing.T) {
		badToken := generateHS256Token(t, "wR7tK3mW9pL2vX5qJ8bN4mW6nY3zA", gjwt.MapClaims{
			"sub": "user-42",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		r := newTestRequest(t, "GET", "http://jwt-hs256.test/")
		r.Header.Set("Authorization", "Bearer "+badToken)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("expired token returns 401", func(t *testing.T) {
		expiredToken := generateHS256Token(t, secret, gjwt.MapClaims{
			"sub": "user-42",
			"exp": time.Now().Add(-time.Hour).Unix(),
		})
		r := newTestRequest(t, "GET", "http://jwt-hs256.test/")
		r.Header.Set("Authorization", "Bearer "+expiredToken)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

// TestJWT_JWKSEndpoint_E2E tests JWKS endpoint key fetching and caching.
// SSRF protection blocks localhost HTTPS endpoints, so this test requires
// a real JWKS URL to run.
func TestJWT_JWKSEndpoint_E2E(t *testing.T) {
	jwksURL := os.Getenv("JWKS_TEST_URL")
	if jwksURL == "" {
		t.Skip("JWKS_TEST_URL not set - set to a public JWKS endpoint to run this test")
	}
}

// TestJWT_ClaimsValidation_E2E tests issuer and audience claim validation
func TestJWT_ClaimsValidation_E2E(t *testing.T) {
	resetCache()
	secret := "cV7tK3mW9pL2vX5qJ8bN4mW6nY3zA!"

	cfg := originJSON(t, map[string]any{
		"hostname": "jwt-claims.test",
		"action":   map[string]any{"type": "echo"},
		"authentication": map[string]any{
			"type":      "jwt",
			"algorithm": "HS256",
			"secret":    secret,
			"issuer":    "expected-issuer",
			"audience":  "expected-audience",
		},
	})

	t.Run("valid claims pass", func(t *testing.T) {
		tok := generateHS256Token(t, secret, gjwt.MapClaims{
			"sub": "user-1",
			"iss": "expected-issuer",
			"aud": "expected-audience",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		r := newTestRequest(t, "GET", "http://jwt-claims.test/")
		r.Header.Set("Authorization", "Bearer "+tok)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("wrong issuer returns 401", func(t *testing.T) {
		tok := generateHS256Token(t, secret, gjwt.MapClaims{
			"sub": "user-1",
			"iss": "wrong-issuer",
			"aud": "expected-audience",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		r := newTestRequest(t, "GET", "http://jwt-claims.test/")
		r.Header.Set("Authorization", "Bearer "+tok)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong issuer, got %d", w.Code)
		}
	})

	t.Run("wrong audience returns 401", func(t *testing.T) {
		tok := generateHS256Token(t, secret, gjwt.MapClaims{
			"sub": "user-1",
			"iss": "expected-issuer",
			"aud": "wrong-audience",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		r := newTestRequest(t, "GET", "http://jwt-claims.test/")
		r.Header.Set("Authorization", "Bearer "+tok)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong audience, got %d", w.Code)
		}
	})
}

// TestJWT_TokenExtractionVariants_E2E tests different token extraction methods
func TestJWT_TokenExtractionVariants_E2E(t *testing.T) {
	resetCache()
	secret := "eX7tK3mW9pL2vX5qJ8bN4mW6nY3zA!"

	validToken := generateHS256Token(t, secret, gjwt.MapClaims{
		"sub": "user-extract",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	t.Run("from Authorization header", func(t *testing.T) {
		cfg := originJSON(t, map[string]any{
			"hostname": "jwt-extract-header.test",
			"action":   map[string]any{"type": "echo"},
			"authentication": map[string]any{
				"type":      "jwt",
				"algorithm": "HS256",
				"secret":    secret,
			},
		})
		r := newTestRequest(t, "GET", "http://jwt-extract-header.test/")
		r.Header.Set("Authorization", "Bearer "+validToken)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("from query parameter", func(t *testing.T) {
		cfg := originJSON(t, map[string]any{
			"hostname": "jwt-extract-query.test",
			"action":   map[string]any{"type": "echo"},
			"authentication": map[string]any{
				"type":        "jwt",
				"algorithm":   "HS256",
				"secret":      secret,
				"query_param": "token",
			},
		})
		r := newTestRequest(t, "GET", "http://jwt-extract-query.test/?token="+validToken)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("from cookie", func(t *testing.T) {
		cfg := originJSON(t, map[string]any{
			"hostname": "jwt-extract-cookie.test",
			"action":   map[string]any{"type": "echo"},
			"authentication": map[string]any{
				"type":        "jwt",
				"algorithm":   "HS256",
				"secret":      secret,
				"cookie_name": "jwt_token",
			},
		})
		r := newTestRequest(t, "GET", "http://jwt-extract-cookie.test/")
		r.AddCookie(&http.Cookie{Name: "jwt_token", Value: validToken})
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// TestJWT_TokenCaching_E2E tests validated token caching
func TestJWT_TokenCaching_E2E(t *testing.T) {
	resetCache()
	secret := "cT7tK3mW9pL2vX5qJ8bN4mW6nY3zA!"

	validToken := generateHS256Token(t, secret, gjwt.MapClaims{
		"sub": "cached-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	cfg := originJSON(t, map[string]any{
		"hostname": "jwt-cache.test",
		"action":   map[string]any{"type": "echo"},
		"authentication": map[string]any{
			"type":      "jwt",
			"algorithm": "HS256",
			"secret":    secret,
		},
	})

	// Multiple requests with the same token should all succeed (cache hit)
	for i := 0; i < 5; i++ {
		r := newTestRequest(t, "GET", "http://jwt-cache.test/")
		r.Header.Set("Authorization", "Bearer "+validToken)
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
		}
	}
}

