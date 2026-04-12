// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/lib/pq"
)

func init() {
	Register("database", NewDatabaseStorage)
}

// DatabaseStorage implements ConfigStorage interface with a custom query
type DatabaseStorage struct {
	db     *sql.DB
	query  string
	driver string
}

// Get retrieves a value from the DatabaseStorage.
func (s *DatabaseStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var data []byte
	err := s.db.QueryRowContext(ctx, s.query, key).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	return data, nil
}

// GetByID returns the by id for the DatabaseStorage.
func (s *DatabaseStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	// Not supported for custom query storage yet
	return nil, fmt.Errorf("GetByID not supported for custom query storage")
}

// Put performs the put operation on the DatabaseStorage.
func (s *DatabaseStorage) Put(ctx context.Context, key string, data []byte) error {
	return ErrReadOnly
}

// Delete performs the delete operation on the DatabaseStorage.
func (s *DatabaseStorage) Delete(ctx context.Context, key string) error {
	return ErrReadOnly
}

// DeleteByPrefix performs the delete by prefix operation on the DatabaseStorage.
func (s *DatabaseStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	return ErrReadOnly
}

// Close releases resources held by the DatabaseStorage.
func (s *DatabaseStorage) Close() error {
	return s.db.Close()
}

// Driver performs the driver operation on the DatabaseStorage.
func (s *DatabaseStorage) Driver() string {
	return s.driver
}

// ListKeys performs the list keys operation on the DatabaseStorage.
func (s *DatabaseStorage) ListKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, "SELECT key FROM config_storage")
	if err != nil {
		return nil, fmt.Errorf("ListKeys not supported for custom query storage: %w", err)
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

// ListKeysByWorkspace performs the list keys by workspace operation on the DatabaseStorage.
func (s *DatabaseStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM config_storage")
	if err != nil {
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

// ValidateProxyAPIKey performs the validate proxy api key operation on the DatabaseStorage.
func (s *DatabaseStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	return nil, fmt.Errorf("ValidateProxyAPIKey not supported for database storage - use http storage instead")
}

// NewDatabaseStorage creates and initializes a new DatabaseStorage.
func NewDatabaseStorage(settings Settings) (Storage, error) {
	dsn, ok := settings.Params["dsn"]
	if !ok {
		return nil, fmt.Errorf("database storage: dsn is required")
	}

	query, ok := settings.Params["query"]
	if !ok {
		return nil, fmt.Errorf("database storage: query is required")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	return &DatabaseStorage{
		db:     db,
		query:  query,
		driver: "database",
	}, nil
}
