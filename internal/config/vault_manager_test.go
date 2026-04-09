package config

import (
	"context"
	"testing"
)

func TestVaultManager_ResolveAll_SystemSecrets(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)
	mock.SetSecret("/gateway/cb-secret", "my-callback-secret")
	mock.SetSecret("/gateway/api-key", "sk-12345")

	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("NewVaultManager() error: %v", err)
	}

	vm.SetSecretDefinitions(map[string]string{
		"CALLBACK_SECRET": "system:/gateway/cb-secret",
		"API_KEY":         "system:/gateway/api-key",
	})

	if err := vm.ResolveAll(context.Background()); err != nil {
		t.Fatalf("ResolveAll() error: %v", err)
	}

	// Check individual secret retrieval
	val, ok := vm.GetSecret("CALLBACK_SECRET")
	if !ok {
		t.Fatal("GetSecret(CALLBACK_SECRET) returned false")
	}
	if val != "my-callback-secret" {
		t.Errorf("GetSecret(CALLBACK_SECRET) = %q, want %q", val, "my-callback-secret")
	}

	val, ok = vm.GetSecret("API_KEY")
	if !ok {
		t.Fatal("GetSecret(API_KEY) returned false")
	}
	if val != "sk-12345" {
		t.Errorf("GetSecret(API_KEY) = %q, want %q", val, "sk-12345")
	}

	// Check GetAllSecrets
	all := vm.GetAllSecrets()
	if len(all) != 2 {
		t.Fatalf("GetAllSecrets() returned %d items, want 2", len(all))
	}
}

func TestVaultManager_ResolveAll_MixedVaults(t *testing.T) {
	localMock := NewMockVaultProvider(VaultTypeLocal)
	localMock.SetSecret("/vault/token", "hvs.vault-token")
	localMock.SetSecret("/app/db-pass", "pg-secret-123")

	remoteMock := NewMockVaultProvider(VaultTypeHashicorp)
	remoteMock.SetSecret("/kv/data/stripe-key", "sk_live_xyz")

	vm, err := NewVaultManager(localMock)
	if err != nil {
		t.Fatalf("NewVaultManager() error: %v", err)
	}

	// Manually register the remote vault (since createRemoteProvider isn't implemented)
	vm.remoteVaults["hashi"] = remoteMock

	vm.SetSecretDefinitions(map[string]string{
		"VAULT_TOKEN": "system:/vault/token",
		"DB_PASSWORD": "system:/app/db-pass",
		"STRIPE_KEY":  "hashi:/kv/data/stripe-key",
	})

	if err := vm.ResolveAll(context.Background()); err != nil {
		t.Fatalf("ResolveAll() error: %v", err)
	}

	all := vm.GetAllSecrets()
	if len(all) != 3 {
		t.Fatalf("GetAllSecrets() returned %d items, want 3", len(all))
	}

	expected := map[string]string{
		"VAULT_TOKEN": "hvs.vault-token",
		"DB_PASSWORD": "pg-secret-123",
		"STRIPE_KEY":  "sk_live_xyz",
	}
	for k, want := range expected {
		if got := all[k]; got != want {
			t.Errorf("secret %q = %q, want %q", k, got, want)
		}
	}
}

func TestVaultManager_ResolveAll_MissingSecret(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)
	// Intentionally don't set the secret

	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("NewVaultManager() error: %v", err)
	}

	vm.SetSecretDefinitions(map[string]string{
		"MISSING": "system:/does/not/exist",
	})

	err = vm.ResolveAll(context.Background())
	if err == nil {
		t.Fatal("ResolveAll() should fail when a secret is missing")
	}
}

func TestVaultManager_ResolveAll_UnknownVault(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)

	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("NewVaultManager() error: %v", err)
	}

	vm.SetSecretDefinitions(map[string]string{
		"SECRET": "unknown_vault:/some/path",
	})

	err = vm.ResolveAll(context.Background())
	if err == nil {
		t.Fatal("ResolveAll() should fail when vault is unknown")
	}
}

func TestVaultManager_Close(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)
	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("NewVaultManager() error: %v", err)
	}

	remoteMock := NewMockVaultProvider(VaultTypeHashicorp)
	vm.remoteVaults["hashi"] = remoteMock

	if err := vm.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

func TestInterpolateSecretRefs(t *testing.T) {
	secrets := map[string]string{
		"TOKEN":  "bearer-123",
		"API_ID": "app-456",
	}

	tests := []struct {
		input string
		want  string
	}{
		{"Bearer {{secrets.TOKEN}}", "Bearer bearer-123"},
		{"{{secrets.API_ID}}/path", "app-456/path"},
		{"no refs here", "no refs here"},
		{"{{secrets.MISSING}}", "{{secrets.MISSING}}"},
		{"{{secrets.TOKEN}} and {{secrets.API_ID}}", "bearer-123 and app-456"},
	}

	for _, tt := range tests {
		got := interpolateSecretRefs(tt.input, secrets)
		if got != tt.want {
			t.Errorf("interpolateSecretRefs(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
