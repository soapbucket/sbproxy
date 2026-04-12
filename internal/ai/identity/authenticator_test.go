package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

// --- API Key Auth tests ---

func TestAPIKeyAuth_ValidKey(t *testing.T) {
	principal := &Principal{
		ID:          "user-1",
		Type:        CredentialAPIKey,
		Groups:      []string{"admin"},
		Permissions: []string{"chat", "embeddings"},
	}
	auth := NewAPIKeyAuth(map[string]*Principal{
		"test-api-key-123": principal,
	})

	p, err := auth.Authenticate(context.Background(), "test-api-key-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.ID != "user-1" {
		t.Errorf("expected user-1, got %s", p.ID)
	}
	if p.AuthenticatedAt.IsZero() {
		t.Error("expected AuthenticatedAt to be set")
	}
}

func TestAPIKeyAuth_InvalidKey(t *testing.T) {
	auth := NewAPIKeyAuth(map[string]*Principal{
		"valid-key": {ID: "user-1"},
	})

	_, err := auth.Authenticate(context.Background(), "wrong-key")
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestAPIKeyAuth_EmptyKey(t *testing.T) {
	auth := NewAPIKeyAuth(map[string]*Principal{})

	_, err := auth.Authenticate(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty key")
	}
}

func TestAPIKeyAuth_WithConnector(t *testing.T) {
	connector := newMockConnector()
	connector.set("api_key", "dynamic-key", &CachedPermission{
		Principal:   "dynamic-user",
		Groups:      []string{"devs"},
		Permissions: []string{"read"},
	})

	auth := NewAPIKeyAuthWithConnector(map[string]*Principal{}, connector)

	p, err := auth.Authenticate(context.Background(), "dynamic-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.ID != "dynamic-user" {
		t.Errorf("expected dynamic-user, got %s", p.ID)
	}
}

// --- JWT Auth tests ---

func buildTestJWT(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

func TestJWTAuth_ValidToken(t *testing.T) {
	secret := []byte("tR7mK9pL2vX5qJ8bN4mW6nY3zA!!")
	claims := map[string]any{
		"sub":    "user-jwt-1",
		"groups": []string{"admin", "devs"},
		"exp":    float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token := buildTestJWT(t, secret, claims)

	auth := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
	})

	p, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.UserID != "user-jwt-1" {
		t.Errorf("expected user-jwt-1, got %s", p.UserID)
	}
	if p.ID != "user-jwt-1" {
		t.Errorf("expected ID user-jwt-1, got %s", p.ID)
	}
	if len(p.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(p.Groups))
	}
	if p.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}
}

func TestJWTAuth_ExpiredToken(t *testing.T) {
	secret := []byte("tR7mK9pL2vX5qJ8bN4mW6nY3zA!!")
	claims := map[string]any{
		"sub": "user-expired",
		"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
	}

	token := buildTestJWT(t, secret, claims)

	auth := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
	})

	_, err := auth.Authenticate(context.Background(), token)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestJWTAuth_InvalidSignature(t *testing.T) {
	secret := []byte("correct-secret")
	wrongSecret := []byte("wrong-secret")

	claims := map[string]any{
		"sub": "user-bad-sig",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token := buildTestJWT(t, wrongSecret, claims)

	auth := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
	})

	_, err := auth.Authenticate(context.Background(), token)
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestJWTAuth_ClaimsMapping(t *testing.T) {
	secret := []byte("mP7tK3mW9pL2vX5qJ8bN4mW6nY!!")
	claims := map[string]any{
		"user_id":    "custom-user",
		"roles":      []string{"editor"},
		"perms":      []string{"write", "delete"},
		"models":     []string{"gpt-4o"},
		"tenant_id":  "ws-123",
		"exp":        float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token := buildTestJWT(t, secret, claims)

	auth := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
		ClaimsMap: JWTClaimsMapping{
			UserID:      "user_id",
			Groups:      "roles",
			Permissions: "perms",
			Models:      "models",
			WorkspaceID: "tenant_id",
		},
	})

	p, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.UserID != "custom-user" {
		t.Errorf("expected custom-user, got %s", p.UserID)
	}
	if p.WorkspaceID != "ws-123" {
		t.Errorf("expected ws-123, got %s", p.WorkspaceID)
	}
	if len(p.Groups) != 1 || p.Groups[0] != "editor" {
		t.Errorf("expected [editor], got %v", p.Groups)
	}
	if len(p.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(p.Permissions))
	}
	if len(p.Models) != 1 || p.Models[0] != "gpt-4o" {
		t.Errorf("expected [gpt-4o], got %v", p.Models)
	}
}

func TestJWTAuth_MissingClaims(t *testing.T) {
	secret := []byte("test-secret-for-missing-claims!")
	claims := map[string]any{
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token := buildTestJWT(t, secret, claims)

	auth := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
	})

	p, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	// Should use default ID when sub is missing.
	if p.ID != "jwt-unknown" {
		t.Errorf("expected jwt-unknown, got %s", p.ID)
	}
	if len(p.Groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(p.Groups))
	}
}

func TestJWTAuth_IssuerMismatch(t *testing.T) {
	secret := []byte("iS7tK3mW9pL2vX5qJ8bN4mW6nY!")
	claims := map[string]any{
		"sub": "user-iss",
		"iss": "wrong-issuer",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token := buildTestJWT(t, secret, claims)

	auth := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
		Issuer: "expected-issuer",
	})

	_, err := auth.Authenticate(context.Background(), token)
	if err == nil {
		t.Error("expected error for issuer mismatch")
	}
}

func TestJWTAuth_EmptyToken(t *testing.T) {
	auth := NewJWTAuth(JWTAuthConfig{Secret: []byte("secret")})
	_, err := auth.Authenticate(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

// --- OAuth Auth tests ---

func TestOAuthAuth_ValidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"active":    true,
			"sub":       "oauth-user-1",
			"client_id": "client-abc",
			"scope":     "read write",
			"exp":       float64(time.Now().Add(1 * time.Hour).Unix()),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	auth := NewOAuthAuth(OAuthAuthConfig{
		IntrospectURL: srv.URL,
		Timeout:       5 * time.Second,
	})

	p, err := auth.Authenticate(context.Background(), "valid-oauth-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.UserID != "oauth-user-1" {
		t.Errorf("expected oauth-user-1, got %s", p.UserID)
	}
	if len(p.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d: %v", len(p.Permissions), p.Permissions)
	}
}

func TestOAuthAuth_InvalidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"active": false}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	auth := NewOAuthAuth(OAuthAuthConfig{
		IntrospectURL: srv.URL,
	})

	_, err := auth.Authenticate(context.Background(), "invalid-token")
	if err == nil {
		t.Error("expected error for inactive token")
	}
}

func TestOAuthAuth_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "slow"})
	}))
	defer srv.Close()

	auth := NewOAuthAuth(OAuthAuthConfig{
		IntrospectURL: srv.URL,
		Timeout:       50 * time.Millisecond, // Very short timeout.
	})

	_, err := auth.Authenticate(context.Background(), "timeout-token")
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestOAuthAuth_EmptyToken(t *testing.T) {
	auth := NewOAuthAuth(OAuthAuthConfig{IntrospectURL: "http://localhost"})
	_, err := auth.Authenticate(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

// --- Personal Key Auth tests ---

func TestPersonalKeyAuth_StaticKey(t *testing.T) {
	principal := &Principal{
		ID:          "pk-user-1",
		Type:        CredentialPersonalKey,
		UserID:      "uid-pk-1",
		WorkspaceID: "ws-pk-1",
		Permissions: []string{"chat"},
	}

	auth := NewPersonalKeyAuth(PersonalKeyAuthConfig{
		StaticKeys: map[string]*Principal{
			"sbk_live_test123": principal,
		},
	})

	p, err := auth.Authenticate(context.Background(), "sbk_live_test123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.ID != "pk-user-1" {
		t.Errorf("expected pk-user-1, got %s", p.ID)
	}
	if p.AuthenticatedAt.IsZero() {
		t.Error("expected AuthenticatedAt to be set")
	}
}

func TestPersonalKeyAuth_InvalidKey(t *testing.T) {
	auth := NewPersonalKeyAuth(PersonalKeyAuthConfig{
		StaticKeys: map[string]*Principal{
			"sbk_live_real": {ID: "real-user"},
		},
	})

	_, err := auth.Authenticate(context.Background(), "sbk_live_fake")
	if err == nil {
		t.Error("expected error for invalid personal key")
	}
}

func TestPersonalKeyAuth_EmptyKey(t *testing.T) {
	auth := NewPersonalKeyAuth(PersonalKeyAuthConfig{})
	_, err := auth.Authenticate(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty key")
	}
}

func TestPersonalKeyAuth_DynamicValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"valid":        true,
			"user_id":      "dynamic-pk-user",
			"workspace_id": "ws-dynamic",
			"permissions":  []string{"chat", "admin"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	auth := NewPersonalKeyAuth(PersonalKeyAuthConfig{
		ValidatorURL: srv.URL,
	})

	p, err := auth.Authenticate(context.Background(), "sbk_live_dynamic_key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.UserID != "dynamic-pk-user" {
		t.Errorf("expected dynamic-pk-user, got %s", p.UserID)
	}
	if p.WorkspaceID != "ws-dynamic" {
		t.Errorf("expected ws-dynamic, got %s", p.WorkspaceID)
	}
	if len(p.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(p.Permissions))
	}
}

// --- extractStringSlice tests ---

func TestExtractStringSlice(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		key    string
		want   int
	}{
		{
			name:   "array of any",
			claims: map[string]any{"groups": []any{"a", "b", "c"}},
			key:    "groups",
			want:   3,
		},
		{
			name:   "comma-separated string",
			claims: map[string]any{"groups": "a, b, c"},
			key:    "groups",
			want:   3,
		},
		{
			name:   "space-separated string",
			claims: map[string]any{"scope": "read write delete"},
			key:    "scope",
			want:   3,
		},
		{
			name:   "single string",
			claims: map[string]any{"role": "admin"},
			key:    "role",
			want:   1,
		},
		{
			name:   "missing key",
			claims: map[string]any{},
			key:    "missing",
			want:   0,
		},
		{
			name:   "number value",
			claims: map[string]any{"groups": 42},
			key:    "groups",
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractStringSlice(tt.claims, tt.key)
			if len(result) != tt.want {
				t.Errorf("expected %d elements, got %d: %v", tt.want, len(result), result)
			}
		})
	}
}

// --- base64URLDecode tests ---

func TestBase64URLDecode(t *testing.T) {
	t.Run("valid with no padding", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString([]byte("hello"))
		decoded, err := base64URLDecode(encoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(decoded) != "hello" {
			t.Errorf("expected hello, got %s", string(decoded))
		}
	})

	t.Run("empty string", func(t *testing.T) {
		decoded, err := base64URLDecode("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(decoded) != 0 {
			t.Errorf("expected empty, got %v", decoded)
		}
	})
}

// --- Type() method tests ---

func TestAuthenticator_Types(t *testing.T) {
	apiKeyAuth := NewAPIKeyAuth(nil)
	if apiKeyAuth.Type() != CredentialAPIKey {
		t.Errorf("expected api_key, got %s", apiKeyAuth.Type())
	}

	jwtAuth := NewJWTAuth(JWTAuthConfig{Secret: []byte("s")})
	if jwtAuth.Type() != CredentialJWT {
		t.Errorf("expected jwt, got %s", jwtAuth.Type())
	}

	oauthAuth := NewOAuthAuth(OAuthAuthConfig{IntrospectURL: "http://x"})
	if oauthAuth.Type() != CredentialOAuth {
		t.Errorf("expected oauth, got %s", oauthAuth.Type())
	}

	pkAuth := NewPersonalKeyAuth(PersonalKeyAuthConfig{})
	if pkAuth.Type() != CredentialPersonalKey {
		t.Errorf("expected personal_key, got %s", pkAuth.Type())
	}
}

// --- Verify stubAuth implements Authenticator ---

var _ Authenticator = (*stubAuth)(nil)
var _ Authenticator = (*APIKeyAuth)(nil)
var _ Authenticator = (*JWTAuth)(nil)
var _ Authenticator = (*OAuthAuth)(nil)
var _ Authenticator = (*PersonalKeyAuth)(nil)

// --- Verify Authenticator interface with fmt.Stringer-like check ---

func TestAPIKeyAuth_DoesNotMutateOriginal(t *testing.T) {
	original := &Principal{
		ID:   "immutable-user",
		Type: CredentialAPIKey,
	}
	auth := NewAPIKeyAuth(map[string]*Principal{
		"key-1": original,
	})

	p, err := auth.Authenticate(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutating the returned principal should not affect the stored one.
	p.ID = "mutated"

	p2, err := auth.Authenticate(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p2.ID != "immutable-user" {
		t.Errorf("expected original to be unchanged, got %s", p2.ID)
	}
}

// Ensure fmt doesn't panic on any type (basic smoke test).
func TestPrincipal_String(t *testing.T) {
	p := &Principal{
		ID:   "test-user",
		Type: CredentialJWT,
	}
	s := fmt.Sprintf("%+v", p)
	if s == "" {
		t.Error("expected non-empty string representation")
	}
}
