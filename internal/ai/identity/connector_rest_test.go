package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func TestRESTConnector_Resolve_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/resolve" {
			t.Errorf("expected /resolve, got %s", r.URL.Path)
		}

		var req restResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if req.CredentialType != "api_key" || req.Credential != "tK7mR9pL2xQ4nB3" {
			t.Errorf("unexpected request body: %+v", req)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(restResolveResponse{
			Principal:   "user-42",
			Groups:      []string{"admin", "developers"},
			Models:      []string{"gpt-4o", "claude-3"},
			Permissions: []string{"read", "write"},
		})
	}))
	defer server.Close()

	c := NewRESTConnector(server.URL, "test-secret", 5*time.Second)
	perm, err := c.Resolve(context.Background(), "api_key", "tK7mR9pL2xQ4nB3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil {
		t.Fatal("expected non-nil permission")
	}
	if perm.Principal != "user-42" {
		t.Errorf("expected principal user-42, got %s", perm.Principal)
	}
	if len(perm.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(perm.Groups))
	}
	if len(perm.Models) != 2 {
		t.Errorf("expected 2 models, got %d", len(perm.Models))
	}
	if perm.CachedAt.IsZero() {
		t.Error("CachedAt should be set")
	}
	if perm.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}
}

func TestRESTConnector_Resolve_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := NewRESTConnector(server.URL, "", 5*time.Second)
	perm, err := c.Resolve(context.Background(), "api_key", "unknown-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm != nil {
		t.Fatal("expected nil permission for 404")
	}
}

func TestRESTConnector_Resolve_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	c := NewRESTConnector(server.URL, "", 5*time.Second)
	_, err := c.Resolve(context.Background(), "api_key", "tK7mR9pL2xQ4nB3")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestRESTConnector_Resolve_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := NewRESTConnector(server.URL, "", 100*time.Millisecond)
	_, err := c.Resolve(context.Background(), "api_key", "tK7mR9pL2xQ4nB3")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestRESTConnector_HMACSignature(t *testing.T) {
	secret := "my-shared-secret"
	var capturedSig string
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSig = r.Header.Get("X-Signature")
		capturedBody, _ = io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(restResolveResponse{
			Principal: "user-1",
		})
	}))
	defer server.Close()

	c := NewRESTConnector(server.URL, secret, 5*time.Second)
	_, err := c.Resolve(context.Background(), "api_key", "tK7mR9pL2xQ4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedSig == "" {
		t.Fatal("expected X-Signature header to be set")
	}

	// Verify the HMAC signature matches.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(capturedBody)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if capturedSig != expectedSig {
		t.Errorf("HMAC mismatch: got %s, want %s", capturedSig, expectedSig)
	}
}
