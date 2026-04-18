package vault

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretResolver_ResolveSecretName(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)
	mock.SetSecret("/kv/stripe", "sk-live-abc123")
	mock.SetSecret("/kv/github", "ghp-token-xyz")

	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("NewVaultManager() error: %v", err)
	}

	// Set up secret definitions that the VaultManager can resolve
	vm.SetSecretDefinitions(map[string]string{
		"stripe_key":   "system:/kv/stripe",
		"github_token": "system:/kv/github",
	})
	if err := vm.ResolveAll(context.Background()); err != nil {
		t.Fatalf("ResolveAll() error: %v", err)
	}

	sr := NewSecretResolver(vm, map[string]string{
		"stripe_key":   "system:/kv/stripe",
		"github_token": "system:/kv/github",
	}, "reject")

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "resolve secret:name for stripe_key",
			input: "secret:stripe_key",
			want:  "sk-live-abc123",
		},
		{
			name:  "resolve secret:name for github_token",
			input: "secret:github_token",
			want:  "ghp-token-xyz",
		},
		{
			name:    "unknown secret name",
			input:   "secret:unknown",
			wantErr: true,
		},
		{
			name:  "plain text passthrough",
			input: "just-a-string",
			want:  "just-a-string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sr.Resolve(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Resolve(%q) expected error, got %q", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("Resolve(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSecretResolver_ResolveEnvVar(t *testing.T) {
	t.Setenv("TEST_SECRET_RESOLVER_VAR", "env-value-123")

	sr := NewSecretResolver(nil, nil, "reject")

	got, err := sr.Resolve("${TEST_SECRET_RESOLVER_VAR}")
	if err != nil {
		t.Fatalf("Resolve(${env}) unexpected error: %v", err)
	}
	if got != "env-value-123" {
		t.Errorf("Resolve(${env}) = %q, want %q", got, "env-value-123")
	}

	// Unset env var should return error
	_, err = sr.Resolve("${NONEXISTENT_TEST_VAR_XYZ}")
	if err == nil {
		t.Error("Resolve(${unset}) expected error")
	}

	// Empty var name should return error
	_, err = sr.Resolve("${}")
	if err == nil {
		t.Error("Resolve(${}) expected error")
	}
}

func TestSecretResolver_ResolveFile(t *testing.T) {
	// Create a temporary file with secret content
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("file-secret-value\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	sr := NewSecretResolver(nil, nil, "reject")

	got, err := sr.Resolve("file:" + path)
	if err != nil {
		t.Fatalf("Resolve(file:) unexpected error: %v", err)
	}
	// Trailing newline should be trimmed
	if got != "file-secret-value" {
		t.Errorf("Resolve(file:) = %q, want %q", got, "file-secret-value")
	}

	// Non-existent file should return error
	_, err = sr.Resolve("file:/nonexistent/path/secret.txt")
	if err == nil {
		t.Error("Resolve(file:nonexistent) expected error")
	}

	// Empty path should return error
	_, err = sr.Resolve("file:")
	if err == nil {
		t.Error("Resolve(file:) with empty path expected error")
	}
}

func TestSecretResolver_PlainText(t *testing.T) {
	sr := NewSecretResolver(nil, nil, "reject")

	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"", ""},
		{"some-config-value", "some-config-value"},
		{"https://example.com", "https://example.com"},
	}

	for _, tt := range tests {
		got, err := sr.Resolve(tt.input)
		if err != nil {
			t.Fatalf("Resolve(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("Resolve(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSecretResolver_FallbackEnv(t *testing.T) {
	t.Setenv("MY_SECRET", "env-fallback-value")

	sr := NewSecretResolver(nil, map[string]string{
		"my_secret": "system:/missing/path",
	}, "env")

	// The secret can't be resolved via vault (no VaultManager), but should
	// fall back to the environment variable.
	got, err := sr.Resolve("secret:my_secret")
	if err != nil {
		t.Fatalf("Resolve() with env fallback unexpected error: %v", err)
	}
	// It should try uppercase: MY_SECRET
	if got != "env-fallback-value" {
		t.Errorf("Resolve() with env fallback = %q, want %q", got, "env-fallback-value")
	}
}

func TestSecretResolver_FallbackReject(t *testing.T) {
	sr := NewSecretResolver(nil, map[string]string{
		"my_secret": "system:/missing/path",
	}, "reject")

	_, err := sr.Resolve("secret:my_secret")
	if err == nil {
		t.Error("Resolve() with reject fallback expected error")
	}
}

func TestSecretResolver_FallbackCache(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)
	mock.SetSecret("/kv/key", "cached-value")

	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("NewVaultManager() error: %v", err)
	}

	// Pre-populate the cache
	vm.SetSecretDefinitions(map[string]string{
		"my_key": "system:/kv/key",
	})
	if err := vm.ResolveAll(context.Background()); err != nil {
		t.Fatalf("ResolveAll() error: %v", err)
	}

	// Create resolver with a secret map that references an unknown vault path
	// but the VaultManager already has a cached value for "my_key"
	sr := NewSecretResolver(vm, map[string]string{
		"my_key": "other:/kv/missing",
	}, "cache")

	got, err := sr.Resolve("secret:my_key")
	if err != nil {
		t.Fatalf("Resolve() with cache fallback unexpected error: %v", err)
	}
	if got != "cached-value" {
		t.Errorf("Resolve() with cache fallback = %q, want %q", got, "cached-value")
	}
}

func TestNewSecretResolver_Defaults(t *testing.T) {
	sr := NewSecretResolver(nil, nil, "")
	if sr.fallback != "reject" {
		t.Errorf("default fallback = %q, want %q", sr.fallback, "reject")
	}
	if sr.secretMap == nil {
		t.Error("secretMap should not be nil when constructed with nil")
	}
}
