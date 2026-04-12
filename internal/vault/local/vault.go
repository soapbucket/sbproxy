// Package local provides a SQLite-backed local secret vault for development
// and testing. It stores secrets encrypted with AES-256-GCM using the same
// format as the proxy's crypto package (local:<base64(nonce + ciphertext)>).
//
// The vault reads from the same SQLite database as the Python CLI tool
// (tools/secrets/vault.py), so secrets created by either tool are
// interchangeable.
package local

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/soapbucket/sbproxy/internal/security/crypto"
)

// Vault is a SQLite-backed local secret store.
type Vault struct {
	db     *sql.DB
	crypto crypto.Crypto
}

// VaultType is the string identifier used by the config VaultProvider interface.
const VaultType = "local"

// New opens (or creates) a local vault at the given database path.
// The crypto.Crypto must already be initialised with the local encryption key.
func New(dbPath string, c crypto.Crypto) (*Vault, error) {
	slog.Info("opening local vault", "path", dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		slog.Error("failed to open vault database", "path", dbPath, "error", err)
		return nil, fmt.Errorf("vault: failed to open database: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		slog.Error("failed to ping vault database", "path", dbPath, "error", err)
		return nil, fmt.Errorf("vault: failed to ping database: %w", err)
	}

	if err := initTable(db); err != nil {
		db.Close()
		return nil, err
	}

	slog.Info("local vault ready", "path", dbPath)
	return &Vault{db: db, crypto: c}, nil
}

// Type returns the vault type identifier ("local") for the VaultProvider interface.
func (v *Vault) Type() string {
	return VaultType
}

// GetSecret implements the vault.VaultProvider interface. It resolves a secret
// by path from the local SQLite vault, decrypting it on the fly.
func (v *Vault) GetSecret(ctx context.Context, path string) (string, error) {
	value, err := v.Get(ctx, path)
	if err != nil {
		slog.Error("vault GetSecret failed", "path", path, "error", err)
		return "", err
	}
	if value == "" {
		slog.Warn("vault secret not found", "path", path)
		return "", fmt.Errorf("vault: secret not found: %s", path)
	}
	slog.Debug("vault secret resolved", "path", path)
	return value, nil
}

func initTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			path TEXT PRIMARY KEY,
			encrypted_value TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("vault: failed to create table: %w", err)
	}
	return nil
}

// Get retrieves and decrypts a secret by path. Returns empty string and no
// error if the path does not exist.
func (v *Vault) Get(ctx context.Context, path string) (string, error) {
	var encrypted string
	err := v.db.QueryRowContext(ctx, "SELECT encrypted_value FROM secrets WHERE path = ?", path).Scan(&encrypted)
	if err == sql.ErrNoRows {
		slog.Debug("vault get: path not found", "path", path)
		return "", nil
	}
	if err != nil {
		slog.Error("vault get: query failed", "path", path, "error", err)
		return "", fmt.Errorf("vault: get %q: %w", path, err)
	}

	plaintext, err := v.crypto.Decrypt([]byte(encrypted))
	if err != nil {
		slog.Error("vault get: decryption failed", "path", path, "error", err)
		return "", fmt.Errorf("vault: decrypt %q: %w", path, err)
	}
	slog.Debug("vault get: decrypted successfully", "path", path)
	return string(plaintext), nil
}

// GetEncrypted retrieves the raw encrypted value without decrypting.
func (v *Vault) GetEncrypted(ctx context.Context, path string) (string, error) {
	var encrypted string
	err := v.db.QueryRowContext(ctx, "SELECT encrypted_value FROM secrets WHERE path = ?", path).Scan(&encrypted)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("vault: get encrypted %q: %w", path, err)
	}
	return encrypted, nil
}

// Set encrypts and stores a secret at the given path.
func (v *Vault) Set(ctx context.Context, path string, plaintext string) error {
	encrypted, err := v.crypto.Encrypt([]byte(plaintext))
	if err != nil {
		slog.Error("vault set: encryption failed", "path", path, "error", err)
		return fmt.Errorf("vault: encrypt %q: %w", path, err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = v.db.ExecContext(ctx, `
		INSERT INTO secrets (path, encrypted_value, created_at, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET encrypted_value=excluded.encrypted_value, updated_at=excluded.updated_at
	`, path, string(encrypted), now, now)
	if err != nil {
		slog.Error("vault set: database write failed", "path", path, "error", err)
		return fmt.Errorf("vault: set %q: %w", path, err)
	}
	slog.Info("vault set: secret stored", "path", path)
	return nil
}

// Delete removes a secret by path. Returns true if a row was deleted.
func (v *Vault) Delete(ctx context.Context, path string) (bool, error) {
	result, err := v.db.ExecContext(ctx, "DELETE FROM secrets WHERE path = ?", path)
	if err != nil {
		slog.Error("vault delete: failed", "path", path, "error", err)
		return false, fmt.Errorf("vault: delete %q: %w", path, err)
	}
	n, _ := result.RowsAffected()
	if n > 0 {
		slog.Info("vault delete: secret removed", "path", path)
	} else {
		slog.Debug("vault delete: path not found", "path", path)
	}
	return n > 0, nil
}

// Entry represents a secret's metadata (without its value).
type Entry struct {
	Path      string
	CreatedAt string
	UpdatedAt string
}

// List returns metadata for all secrets matching the given prefix.
// An empty prefix returns all entries.
func (v *Vault) List(ctx context.Context, prefix string) ([]Entry, error) {
	var rows *sql.Rows
	var err error
	if prefix == "" {
		rows, err = v.db.QueryContext(ctx, "SELECT path, created_at, updated_at FROM secrets ORDER BY path")
	} else {
		rows, err = v.db.QueryContext(ctx,
			"SELECT path, created_at, updated_at FROM secrets WHERE path LIKE ? ORDER BY path",
			prefix+"%")
	}
	if err != nil {
		return nil, fmt.Errorf("vault: list: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Path, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("vault: list scan: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Resolve resolves a secret reference of the form "system:/path/to/secret".
// It strips the "system:" prefix and looks up the path in the vault.
func (v *Vault) Resolve(ctx context.Context, ref string) (string, error) {
	path := ref
	if strings.HasPrefix(ref, "system:") {
		path = strings.TrimPrefix(ref, "system:")
	}
	value, err := v.Get(ctx, path)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("vault: secret not found: %s", path)
	}
	return value, nil
}

// Close closes the underlying database connection.
func (v *Vault) Close() error {
	return v.db.Close()
}
