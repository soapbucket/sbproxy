package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func serveJWKS(t *testing.T, keys map[string]*rsa.PublicKey) *httptest.Server {
	t.Helper()
	type jwkEntry struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	type jwksResp struct {
		Keys []jwkEntry `json:"keys"`
	}

	resp := jwksResp{}
	for kid, pub := range keys {
		resp.Keys = append(resp.Keys, jwkEntry{
			Kid: kid,
			Kty: "RSA",
			Use: "sig",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal JWKS: %v", err)
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
}

func TestJWKSKeySet_RefreshAndGetKey(t *testing.T) {
	priv := generateTestRSAKey(t)
	server := serveJWKS(t, map[string]*rsa.PublicKey{"key-1": &priv.PublicKey})
	defer server.Close()

	ks := NewJWKSKeySet(JWKSConfig{
		URL:             server.URL,
		RefreshInterval: 1 * time.Hour,
	})

	if err := ks.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	key, err := ks.GetKey("key-1")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if key.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("returned key does not match expected public key")
	}
}

func TestJWKSKeySet_GetKeyNotFound(t *testing.T) {
	priv := generateTestRSAKey(t)
	server := serveJWKS(t, map[string]*rsa.PublicKey{"key-1": &priv.PublicKey})
	defer server.Close()

	ks := NewJWKSKeySet(JWKSConfig{
		URL:             server.URL,
		RefreshInterval: 1 * time.Hour,
	})

	_, err := ks.GetKey("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestJWKSKeySet_AutoRefreshOnGetKey(t *testing.T) {
	priv := generateTestRSAKey(t)
	server := serveJWKS(t, map[string]*rsa.PublicKey{"key-1": &priv.PublicKey})
	defer server.Close()

	ks := NewJWKSKeySet(JWKSConfig{
		URL:             server.URL,
		RefreshInterval: 1 * time.Hour,
	})

	// GetKey should trigger refresh automatically
	key, err := ks.GetKey("key-1")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if key == nil {
		t.Error("expected non-nil key")
	}
}

func TestJWKSKeySet_RefreshEmptyURL(t *testing.T) {
	ks := NewJWKSKeySet(JWKSConfig{})
	err := ks.Refresh(context.Background())
	if err != ErrJWKSEmptyURL {
		t.Errorf("expected ErrJWKSEmptyURL, got %v", err)
	}
}

func TestJWKSKeySet_RefreshBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ks := NewJWKSKeySet(JWKSConfig{URL: server.URL})
	err := ks.Refresh(context.Background())
	if err == nil {
		t.Error("expected error for bad HTTP status")
	}
}

func TestJWKSKeySet_RefreshInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	ks := NewJWKSKeySet(JWKSConfig{URL: server.URL})
	err := ks.Refresh(context.Background())
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestJWKSKeySet_DefaultRefreshInterval(t *testing.T) {
	ks := NewJWKSKeySet(JWKSConfig{URL: "http://example.com"})
	if ks.refreshInterval != defaultJWKSRefreshInterval {
		t.Errorf("expected default refresh interval, got %v", ks.refreshInterval)
	}
}

func TestParseRSAPublicKey_ValidKey(t *testing.T) {
	priv := generateTestRSAKey(t)
	entry := jwksKeySetEntry{
		Kid: "test",
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}

	key, err := parseRSAPublicKey(entry)
	if err != nil {
		t.Fatalf("parseRSAPublicKey failed: %v", err)
	}
	if key.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("modulus mismatch")
	}
	if key.E != priv.PublicKey.E {
		t.Error("exponent mismatch")
	}
}

func TestParseRSAPublicKey_InvalidModulus(t *testing.T) {
	entry := jwksKeySetEntry{
		Kid: "test",
		Kty: "RSA",
		N:   "!!!invalid!!!",
		E:   "AQAB",
	}

	_, err := parseRSAPublicKey(entry)
	if err == nil {
		t.Error("expected error for invalid modulus")
	}
}

func TestParseRSAPublicKey_InvalidExponent(t *testing.T) {
	priv := generateTestRSAKey(t)
	entry := jwksKeySetEntry{
		Kid: "test",
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   "!!!invalid!!!",
	}

	_, err := parseRSAPublicKey(entry)
	if err == nil {
		t.Error("expected error for invalid exponent")
	}
}
