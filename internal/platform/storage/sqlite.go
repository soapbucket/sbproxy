// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	_ "modernc.org/sqlite"
)

func init() {
	Register(DriverSQLite, NewSQLiteStorage)
}

// NewSQLiteStorage creates and initializes a new SQLiteStorage.
func NewSQLiteStorage(settings Settings) (Storage, error) {
	// Get path from params
	path, ok := settings.Params[ParamPath]
	if !ok {
		return nil, ErrInvalidConfiguration
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		slog.Error("failed to open database", "error", err, "path", path)
		return nil, err
	}

	// SQLite does not support concurrent writes; limit to 1 open connection
	db.SetMaxOpenConns(1)

	// Verify connectivity
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, err
	}

	// Initialize table if it doesn't exist
	if err := initSQLiteTable(db); err != nil {
		db.Close()
		return nil, err
	}

	return &SQLiteStorage{db: db, driver: settings.Driver}, nil
}

func initSQLiteTable(db *sql.DB) error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS config_storage (
		id TEXT PRIMARY KEY,
		key TEXT NOT NULL UNIQUE,
		value BLOB NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := db.Exec(createTableSQL)
	if err != nil {
		slog.Error("failed to create table", "error", err)
		return err
	}

	// Create index on key
	createIndexSQL := `CREATE INDEX IF NOT EXISTS idx_config_storage_key ON config_storage(key)`
	_, err = db.Exec(createIndexSQL)
	if err != nil {
		slog.Error("failed to create index", "error", err)
		return err
	}

	return nil
}

// SQLiteStorage represents a sq lite storage.
type SQLiteStorage struct {
	db     *sql.DB
	driver string
}

// Get retrieves a value from the SQLiteStorage.
func (s *SQLiteStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return nil, err
	}

	var value []byte
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM config_storage WHERE key = ? LIMIT 1", key).Scan(&value); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	return value, nil
}

// GetByID returns the by id for the SQLiteStorage.
func (s *SQLiteStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return nil, err
	}

	var value []byte
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM config_storage WHERE id = ?", id).Scan(&value); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	return value, nil
}

// Put performs the put operation on the SQLiteStorage.
func (s *SQLiteStorage) Put(ctx context.Context, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return err
	}

	// Generate a new UUID for the id
	id := uuid.New().String()

	// Try to update existing record first, if no rows affected then insert
	result, err := s.db.ExecContext(ctx, "UPDATE config_storage SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?", data, key)
	if err != nil {
		slog.Error("failed to update record", "error", err, "key", key)
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		slog.Error("failed to get rows affected", "error", err)
		return err
	}

	// If no rows were updated, insert new record
	if rowsAffected == 0 {
		_, err = s.db.ExecContext(ctx, "INSERT INTO config_storage (id, key, value) VALUES (?, ?, ?)", id, key, data)
		if err != nil {
			slog.Error("failed to insert record", "error", err, "key", key)
			return err
		}
	}

	return nil
}

// Delete performs the delete operation on the SQLiteStorage.
func (s *SQLiteStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return err
	}

	_, err := s.db.ExecContext(ctx, "DELETE FROM config_storage WHERE key = ?", key)
	if err != nil {
		slog.Error("failed to execute delete query", "error", err, "key", key)
		return err
	}

	return nil
}

// DeleteByPrefix performs the delete by prefix operation on the SQLiteStorage.
func (s *SQLiteStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return err
	}

	_, err := s.db.ExecContext(ctx, "DELETE FROM config_storage WHERE key LIKE ?", prefix+"%")
	if err != nil {
		slog.Error("failed to execute delete query", "error", err, "prefix", prefix)
		return err
	}

	return nil
}

// Close releases resources held by the SQLiteStorage.
func (s *SQLiteStorage) Close() error {
	if err := s.db.Close(); err != nil {
		slog.Error("failed to close database", "error", err)
		return err
	}
	return nil
}

// Driver returns the driver name
func (s *SQLiteStorage) Driver() string {
	return s.driver
}

// ListKeys performs the list keys operation on the SQLiteStorage.
func (s *SQLiteStorage) ListKeys(ctx context.Context) ([]string, error) {
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

// ListKeysByWorkspace performs the list keys by workspace operation on the SQLiteStorage.
func (s *SQLiteStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM config_storage")
	if err != nil {
		slog.Error("failed to list keys for workspace filtering", "error", err)
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		var meta struct {
			WorkspaceID string `json:"workspace_id"`
		}
		if json.Unmarshal(value, &meta) == nil && meta.WorkspaceID == workspaceID {
			keys = append(keys, key)
		}
	}
	return keys, rows.Err()
}

// ValidateProxyAPIKey performs the validate proxy api key operation on the SQLiteStorage.
func (s *SQLiteStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	return nil, fmt.Errorf("ValidateProxyAPIKey not supported for sqlite storage - use http storage instead")
}
