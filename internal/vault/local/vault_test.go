package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/soapbucket/sbproxy/internal/security/crypto"
)

const testKeyB64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func newTestVault(t *testing.T) *Vault {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test_vault.db")

	c, err := crypto.NewLocalCrypto(crypto.Settings{
		Driver: "local",
		Params: map[string]string{
			"encryption_key": testKeyB64,
		},
	})
	if err != nil {
		t.Fatalf("failed to create crypto: %v", err)
	}

	v, err := New(dbPath, c)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestSetAndGet(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()

	err := v.Set(ctx, "/test/secret", "my-secret-value")
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	value, err := v.Get(ctx, "/test/secret")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if value != "my-secret-value" {
		t.Errorf("expected %q, got %q", "my-secret-value", value)
	}
}

func TestGetNonExistent(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()

	value, err := v.Get(ctx, "/does/not/exist")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if value != "" {
		t.Errorf("expected empty string, got %q", value)
	}
}

func TestOverwrite(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()

	v.Set(ctx, "/test/key", "value1")
	v.Set(ctx, "/test/key", "value2")

	value, err := v.Get(ctx, "/test/key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if value != "value2" {
		t.Errorf("expected %q, got %q", "value2", value)
	}
}

func TestDelete(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()

	v.Set(ctx, "/test/del", "to-delete")

	deleted, err := v.Delete(ctx, "/test/del")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if !deleted {
		t.Error("expected deleted=true")
	}

	value, _ := v.Get(ctx, "/test/del")
	if value != "" {
		t.Errorf("expected empty after delete, got %q", value)
	}

	deleted, _ = v.Delete(ctx, "/test/del")
	if deleted {
		t.Error("expected deleted=false for non-existent key")
	}
}

func TestList(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()

	v.Set(ctx, "/workspace/a/SECRET_A", "a")
	v.Set(ctx, "/workspace/a/SECRET_B", "b")
	v.Set(ctx, "/workspace/b/SECRET_C", "c")

	// List all
	entries, err := v.List(ctx, "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}

	// List with prefix
	entries, err = v.List(ctx, "/workspace/a")
	if err != nil {
		t.Fatalf("List with prefix failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestGetEncrypted(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()

	v.Set(ctx, "/test/enc", "plaintext-value")

	encrypted, err := v.GetEncrypted(ctx, "/test/enc")
	if err != nil {
		t.Fatalf("GetEncrypted failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("expected non-empty encrypted value")
	}
	if encrypted == "plaintext-value" {
		t.Error("GetEncrypted should return encrypted, not plaintext")
	}
	// Should have local: prefix
	if len(encrypted) < 7 || encrypted[:6] != "local:" {
		t.Errorf("expected local: prefix, got %q", encrypted[:10])
	}
}

func TestResolve(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()

	v.Set(ctx, "/gateway/callback-secret", "cb-secret-123")

	// With system: prefix
	value, err := v.Resolve(ctx, "system:/gateway/callback-secret")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if value != "cb-secret-123" {
		t.Errorf("expected %q, got %q", "cb-secret-123", value)
	}

	// Without prefix
	value, err = v.Resolve(ctx, "/gateway/callback-secret")
	if err != nil {
		t.Fatalf("Resolve without prefix failed: %v", err)
	}
	if value != "cb-secret-123" {
		t.Errorf("expected %q, got %q", "cb-secret-123", value)
	}

	// Non-existent
	_, err = v.Resolve(ctx, "system:/does/not/exist")
	if err == nil {
		t.Error("expected error for non-existent secret")
	}
}

func TestCrossCompatibility(t *testing.T) {
	// Verify that values encrypted by the vault can be decrypted by the
	// standalone crypto package, and vice-versa. This ensures the Python
	// CLI tool's output is also compatible.
	v := newTestVault(t)
	ctx := context.Background()

	c, _ := crypto.NewLocalCrypto(crypto.Settings{
		Driver: "local",
		Params: map[string]string{
			"encryption_key": testKeyB64,
		},
	})

	// Vault -> Crypto
	v.Set(ctx, "/compat/test", "cross-compat-value")
	encrypted, _ := v.GetEncrypted(ctx, "/compat/test")
	decrypted, err := c.Decrypt([]byte(encrypted))
	if err != nil {
		t.Fatalf("crypto.Decrypt of vault-encrypted value failed: %v", err)
	}
	if string(decrypted) != "cross-compat-value" {
		t.Errorf("expected %q, got %q", "cross-compat-value", string(decrypted))
	}

	// Crypto -> Vault (simulate storing a value encrypted outside the vault)
	ciphertext, err := c.Encrypt([]byte("external-encrypted"))
	if err != nil {
		t.Fatalf("crypto.Encrypt failed: %v", err)
	}
	// Insert directly into the database
	now := "2024-01-01T00:00:00Z"
	v.db.Exec(
		"INSERT INTO secrets (path, encrypted_value, created_at, updated_at) VALUES (?, ?, ?, ?)",
		"/compat/external", string(ciphertext), now, now,
	)
	value, err := v.Get(ctx, "/compat/external")
	if err != nil {
		t.Fatalf("vault.Get of crypto-encrypted value failed: %v", err)
	}
	if value != "external-encrypted" {
		t.Errorf("expected %q, got %q", "external-encrypted", value)
	}
}

func TestNewVaultCreatesFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "subdir", "new_vault.db")

	// Parent dir doesn't exist yet - os.MkdirAll the parent
	os.MkdirAll(filepath.Dir(dbPath), 0o755)

	c, _ := crypto.NewLocalCrypto(crypto.Settings{
		Driver: "local",
		Params: map[string]string{
			"encryption_key": testKeyB64,
		},
	})

	v, err := New(dbPath, c)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer v.Close()

	// Should be able to use it
	ctx := context.Background()
	v.Set(ctx, "/hello", "world")
	value, _ := v.Get(ctx, "/hello")
	if value != "world" {
		t.Errorf("expected %q, got %q", "world", value)
	}
}
