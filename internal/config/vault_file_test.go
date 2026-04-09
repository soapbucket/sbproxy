package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/soapbucket/sbproxy/internal/security/crypto"
)

func TestFileVaultJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	if err := os.WriteFile(path, []byte(`{"api_key":"abc123","db_pass":"hunter2"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := NewFileVaultProvider(VaultDefinition{Type: VaultTypeFile, Address: path})
	if err != nil {
		t.Fatal(err)
	}

	if p.Type() != VaultTypeFile {
		t.Fatalf("expected type %q, got %q", VaultTypeFile, p.Type())
	}

	val, err := p.GetSecret(context.Background(), "api_key")
	if err != nil {
		t.Fatal(err)
	}
	if val != "abc123" {
		t.Fatalf("expected abc123, got %q", val)
	}

	val, err = p.GetSecret(context.Background(), "db_pass")
	if err != nil {
		t.Fatal(err)
	}
	if val != "hunter2" {
		t.Fatalf("expected hunter2, got %q", val)
	}
}

func TestFileVaultYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yml")
	content := "api_key: abc123\ndb_pass: hunter2\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := NewFileVaultProvider(VaultDefinition{Type: VaultTypeFile, Address: path})
	if err != nil {
		t.Fatal(err)
	}

	val, err := p.GetSecret(context.Background(), "api_key")
	if err != nil {
		t.Fatal(err)
	}
	if val != "abc123" {
		t.Fatalf("expected abc123, got %q", val)
	}
}

func TestFileVaultEncrypted(t *testing.T) {
	// Generate a key and encrypt a value.
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	c, err := crypto.NewCrypto(crypto.Settings{
		Driver: "local",
		Params: map[string]string{crypto.ParamEncryptionKey: key},
	})
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := c.Encrypt([]byte("supersecret"))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	raw := `{"token":"` + string(encrypted) + `"}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := NewFileVaultProvider(VaultDefinition{
		Type:        VaultTypeFile,
		Address:     path,
		Credentials: key,
	})
	if err != nil {
		t.Fatal(err)
	}

	val, err := p.GetSecret(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if val != "supersecret" {
		t.Fatalf("expected supersecret, got %q", val)
	}
}

func TestFileVaultMissingFile(t *testing.T) {
	_, err := NewFileVaultProvider(VaultDefinition{Type: VaultTypeFile, Address: "/nonexistent/path.json"})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFileVaultMissingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	if err := os.WriteFile(path, []byte(`{"a":"1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := NewFileVaultProvider(VaultDefinition{Type: VaultTypeFile, Address: path})
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.GetSecret(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestFileVaultBadExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := NewFileVaultProvider(VaultDefinition{Type: VaultTypeFile, Address: path})
	if err == nil {
		t.Fatal("expected error for unsupported extension")
	}
}

func TestFileVaultEmptyAddress(t *testing.T) {
	_, err := NewFileVaultProvider(VaultDefinition{Type: VaultTypeFile})
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestFileVaultClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := NewFileVaultProvider(VaultDefinition{Type: VaultTypeFile, Address: path})
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
