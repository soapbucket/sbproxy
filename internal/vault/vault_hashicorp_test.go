package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHashicorpVaultProvider_GetSecret_WithFieldSelector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(vaultTokenHeader); got != "vt_9a8b7c6d5e4f3a2b" {
			t.Fatalf("vault token header = %q, want %q", got, "vt_9a8b7c6d5e4f3a2b")
		}
		if got := r.Header.Get(vaultNamespaceHeader); got != "team-a" {
			t.Fatalf("vault namespace header = %q, want %q", got, "team-a")
		}
		if got := r.URL.Path; got != "/v1/secret/data/app" {
			t.Fatalf("request path = %q, want %q", got, "/v1/secret/data/app")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"api_key":"sk-live-123"}}}`))
	}))
	defer server.Close()

	provider, err := NewHashicorpVaultProvider(VaultDefinition{
		Type:      VaultTypeHashicorp,
		Address:   server.URL,
		Namespace: "team-a",
	}, "vt_9a8b7c6d5e4f3a2b")
	if err != nil {
		t.Fatalf("NewHashicorpVaultProvider() error: %v", err)
	}

	got, err := provider.GetSecret(context.Background(), "secret/data/app#api_key")
	if err != nil {
		t.Fatalf("GetSecret() error: %v", err)
	}
	if got != "sk-live-123" {
		t.Fatalf("GetSecret() = %q, want %q", got, "sk-live-123")
	}
}

func TestHashicorpVaultProvider_GetSecret_DefaultValueField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"db-password"}}}`))
	}))
	defer server.Close()

	provider, err := NewHashicorpVaultProvider(VaultDefinition{
		Type:    VaultTypeHashicorp,
		Address: server.URL,
	}, "vt_9a8b7c6d5e4f3a2b")
	if err != nil {
		t.Fatalf("NewHashicorpVaultProvider() error: %v", err)
	}

	got, err := provider.GetSecret(context.Background(), "secret/data/database")
	if err != nil {
		t.Fatalf("GetSecret() error: %v", err)
	}
	if got != "db-password" {
		t.Fatalf("GetSecret() = %q, want %q", got, "db-password")
	}
}

func TestVaultManager_CreateRemoteProvider_Hashicorp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(vaultTokenHeader); got != "vt_x7y6z5w4v3u2t1s0" {
			t.Fatalf("vault token header = %q, want %q", got, "vt_x7y6z5w4v3u2t1s0")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"ok"}}}`))
	}))
	defer server.Close()

	local := NewMockVaultProvider(VaultTypeLocal)
	local.SetSecret("/vault/token", "vt_x7y6z5w4v3u2t1s0")

	vm, err := NewVaultManager(local)
	if err != nil {
		t.Fatalf("NewVaultManager() error: %v", err)
	}

	provider, err := vm.createRemoteProvider(context.Background(), "hashi", VaultDefinition{
		Type:        VaultTypeHashicorp,
		Address:     server.URL,
		AuthMethod:  "token",
		Credentials: "system:/vault/token",
	}, map[string]string{})
	if err != nil {
		t.Fatalf("createRemoteProvider() error: %v", err)
	}

	got, err := provider.GetSecret(context.Background(), "secret/data/health")
	if err != nil {
		t.Fatalf("GetSecret() error: %v", err)
	}
	if got != "ok" {
		t.Fatalf("GetSecret() = %q, want %q", got, "ok")
	}
}

func TestVaultManager_CreateRemoteProvider_HashicorpUnsupportedAuthMethod(t *testing.T) {
	local := NewMockVaultProvider(VaultTypeLocal)
	vm, err := NewVaultManager(local)
	if err != nil {
		t.Fatalf("NewVaultManager() error: %v", err)
	}

	_, err = vm.createRemoteProvider(context.Background(), "hashi", VaultDefinition{
		Type:        VaultTypeHashicorp,
		Address:     "https://vault.example.com",
		AuthMethod:  "kubernetes",
		Credentials: "system:/vault/token",
	}, map[string]string{})
	if err == nil {
		t.Fatal("createRemoteProvider() should fail for unsupported auth_method")
	}
}
