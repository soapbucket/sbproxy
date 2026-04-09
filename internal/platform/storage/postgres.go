// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	_ "github.com/lib/pq"
)

func init() {
	Register(DriverPostgres, NewPostgresStorage)
}

// NewPostgresStorage creates a new Postgres storage instance.
// For Postgres, the full DSN is used as the connection string.
// Supports formats like: postgres://user:pass@host:5432/dbname?sslmode=disable
func NewPostgresStorage(settings Settings) (Storage, error) {
	// Get DSN from params
	dsn, ok := settings.Params[ParamDSN]
	if !ok {
		return nil, ErrInvalidConfiguration
	}

	// For postgres, we use the full DSN (connection string/URL)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	// Verify connectivity
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, err
	}

	// Set statement timeout to prevent runaway queries (5 seconds)
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(timeoutCtx, "SET statement_timeout = '5000'"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set statement_timeout: %w", err)
	}

	// Initialize table if it doesn't exist
	if err := initPostgresTable(db); err != nil {
		db.Close()
		return nil, err
	}

	return &PostgresStorage{db: db, driver: settings.Driver}, nil
}

func initPostgresTable(db *sql.DB) error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS config_storage (
		id UUID PRIMARY KEY,
		key VARCHAR(255) NOT NULL,
		value BYTEA NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := db.Exec(createTableSQL)
	if err != nil {
		slog.Error("failed to create table", "error", err)
		return err
	}

	// Create unique index on key (required for ON CONFLICT upsert)
	createIndexSQL := `CREATE UNIQUE INDEX IF NOT EXISTS idx_config_storage_key ON config_storage(key)`
	_, err = db.Exec(createIndexSQL)
	if err != nil {
		slog.Error("failed to create index", "error", err)
		return err
	}

	return nil
}

// PostgresStorage represents a postgres storage.
type PostgresStorage struct {
	db     *sql.DB
	driver string
}

// Get retrieves a value from the PostgresStorage.
func (s *PostgresStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return nil, err
	}

	var value []byte
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM config_storage WHERE key = $1 LIMIT 1", key).Scan(&value); err != nil {
		return nil, err
	}

	return value, nil
}

// GetByID returns the by id for the PostgresStorage.
func (s *PostgresStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return nil, err
	}

	var value []byte
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM config_storage WHERE id = $1", id).Scan(&value); err != nil {
		return nil, err
	}

	return value, nil
}

// Put performs the put operation on the PostgresStorage.
func (s *PostgresStorage) Put(ctx context.Context, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return err
	}

	id := uuid.New().String()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO config_storage (id, key, value) VALUES ($1, $2, $3)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP`,
		id, key, data)
	if err != nil {
		slog.Error("failed to upsert record", "error", err, "key", key)
		return err
	}

	return nil
}

// Delete performs the delete operation on the PostgresStorage.
func (s *PostgresStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return err
	}

	_, err := s.db.ExecContext(ctx, "DELETE FROM config_storage WHERE key = $1", key)
	if err != nil {
		slog.Error("failed to execute delete query", "error", err, "key", key)
		return err
	}

	return nil
}

// DeleteByPrefix performs the delete by prefix operation on the PostgresStorage.
func (s *PostgresStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return err
	}

	_, err := s.db.ExecContext(ctx, "DELETE FROM config_storage WHERE key LIKE $1", prefix+"%")
	if err != nil {
		slog.Error("failed to execute delete query", "error", err, "prefix", prefix)
		return err
	}

	return nil
}

// Close releases resources held by the PostgresStorage.
func (s *PostgresStorage) Close() error {
	return s.db.Close()
}

// Driver returns the driver name
func (s *PostgresStorage) Driver() string {
	return s.driver
}

// ListKeys performs the list keys operation on the PostgresStorage.
func (s *PostgresStorage) ListKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, "SELECT key FROM config_storage")
	if err != nil {
		slog.Error("failed to list keys", "error", err)
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// ListKeysByWorkspace performs the list keys by workspace operation on the PostgresStorage.
func (s *PostgresStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		"SELECT key FROM config_storage WHERE value::jsonb->>'workspace_id' = $1", workspaceID)
	if err != nil {
		slog.Error("failed to list keys by workspace", "error", err, "workspace_id", workspaceID)
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// ValidateProxyAPIKey performs the validate proxy api key operation on the PostgresStorage.
func (s *PostgresStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	return nil, fmt.Errorf("ValidateProxyAPIKey not supported for postgres storage - use http storage instead")
}
