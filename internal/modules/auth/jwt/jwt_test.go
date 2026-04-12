package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v4"
	jwtmod "github.com/soapbucket/sbproxy/internal/modules/auth/jwt"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

const testSecret = "nR7tK3mW9pL2vX5qJ8bN4"

func makeHMACToken(t *testing.T, claims gjwt.MapClaims) string {
	t.Helper()
	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"type":"jwt","secret":"` + testSecret + `","algorithm":"HS256"}`)
	p, err := jwtmod.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := jwtmod.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_DefaultAlgorithm(t *testing.T) {
	// Without specifying algorithm, default should be RS256.
	p, err := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"test"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Type() != "jwt" {
		t.Errorf("Type() = %q, want %q", p.Type(), "jwt")
	}
}

func TestType(t *testing.T) {
	p, _ := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"test","algorithm":"HS256"}`))
	if p.Type() != "jwt" {
		t.Errorf("Type() = %q, want %q", p.Type(), "jwt")
	}
}

func TestWrap_ValidToken(t *testing.T) {
	p, _ := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"` + testSecret + `","algorithm":"HS256"}`))

	tokenStr := makeHMACToken(t, gjwt.MapClaims{
		"sub": "user123",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called for valid token")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestWrap_ExpiredToken(t *testing.T) {
	p, _ := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"` + testSecret + `","algorithm":"HS256"}`))

	tokenStr := makeHMACToken(t, gjwt.MapClaims{
		"sub": "user123",
		"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called for expired token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_MissingToken(t *testing.T) {
	p, _ := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"` + testSecret + `","algorithm":"HS256"}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called when token is missing")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_InvalidSignature(t *testing.T) {
	p, _ := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"` + testSecret + `","algorithm":"HS256"}`))

	// Sign with a different key.
	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, gjwt.MapClaims{
		"sub": "user123",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})
	tokenStr, _ := token.SignedString([]byte("wrong-secret"))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called for invalid signature")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_IssuerValidation(t *testing.T) {
	p, _ := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"` + testSecret + `","algorithm":"HS256","issuer":"https://auth.example.com"}`))

	// Token with wrong issuer.
	tokenStr := makeHMACToken(t, gjwt.MapClaims{
		"sub": "user123",
		"iss": "https://evil.example.com",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called for wrong issuer")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_CookieExtraction(t *testing.T) {
	p, _ := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"` + testSecret + `","algorithm":"HS256","cookie_name":"jwt_token"}`))

	tokenStr := makeHMACToken(t, gjwt.MapClaims{
		"sub": "user123",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "jwt_token", Value: tokenStr})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called with cookie token")
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAuth("jwt")
	if !ok {
		t.Error("jwt auth not registered in plugin registry")
	}
}

// makeNoneAlgToken builds a JWT with "alg": "none" in the header
// and an empty signature, mimicking the classic "none" algorithm attack.
func makeNoneAlgToken(t *testing.T, claims gjwt.MapClaims) string {
	t.Helper()
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	// "none" algorithm tokens have an empty signature segment
	return headerB64 + "." + claimsB64 + "."
}

func TestWrap_NoneAlgorithmRejected(t *testing.T) {
	// The provider is configured for HS256. A token with alg=none must be rejected.
	p, err := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"` + testSecret + `","algorithm":"HS256"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tokenStr := makeNoneAlgToken(t, gjwt.MapClaims{
		"sub": "attacker",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler must NOT be called for alg=none token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_NoneAlgorithmRejected_RS256(t *testing.T) {
	// Even when configured for RS256, a none-alg token must be rejected.
	p, err := jwtmod.New(json.RawMessage(`{"type":"jwt","public_key":"dummykey","algorithm":"RS256"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tokenStr := makeNoneAlgToken(t, gjwt.MapClaims{
		"sub": "attacker",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler must NOT be called for alg=none token against RS256")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_EmptySignatureRejected(t *testing.T) {
	// A token with a valid HS256 header but with the signature segment stripped.
	p, err := jwtmod.New(json.RawMessage(`{"type":"jwt","secret":"` + testSecret + `","algorithm":"HS256"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Create a legitimate token, then strip the signature.
	validToken := makeHMACToken(t, gjwt.MapClaims{
		"sub": "user123",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})
	parts := strings.SplitN(validToken, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	// Empty the signature segment
	strippedToken := parts[0] + "." + parts[1] + "."

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+strippedToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler must NOT be called for token with empty signature")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWrap_AlgorithmConfusionRejected(t *testing.T) {
	// Provider expects RS256, but attacker sends HS256 token signed with a
	// public key string as HMAC secret. The provider must reject algorithm mismatch.
	p, err := jwtmod.New(json.RawMessage(`{"type":"jwt","public_key":"dummykey","algorithm":"RS256"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Create an HS256 token (algorithm confusion attack)
	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, gjwt.MapClaims{
		"sub": "attacker",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	})
	tokenStr, _ := token.SignedString([]byte("dummykey"))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler must NOT be called for algorithm confusion attack")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
