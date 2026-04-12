// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	cd "github.com/colinmarc/cdb"
)

func init() {
	Register(DriverCDB, NewCDBStorage)
}

// CDBStorage provides read-only access to CDB (Constant Database) files.
// CDB is a fast, immutable key-value database format designed for read-heavy workloads.
// Write operations (Put, Delete, DeleteByPrefix) are not supported and will return ErrReadOnly.
type CDBStorage struct {
	db     *cd.CDB
	driver string
}

// Get retrieves a value by key from the CDB storage.
// Returns ErrKeyNotFound if the key doesn't exist.
func (s *CDBStorage) Get(ctx context.Context, key string) ([]byte, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return nil, err
	}

	data, err := s.db.Get([]byte(key))
	if err != nil {
		slog.Error("failed to retrieve key", "key", key, "error", err)
		return nil, err
	}

	// CDB returns nil data when key is not found (no error)
	if data == nil {
		return nil, ErrKeyNotFound
	}

	return data, nil
}

// GetByID retrieves a value by ID from the CDB storage.
// In CDB, IDs are treated as keys, so this is equivalent to Get.
// Returns ErrKeyNotFound if the ID doesn't exist.
func (s *CDBStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return nil, err
	}

	data, err := s.db.Get([]byte(id))
	if err != nil {
		slog.Error("failed to retrieve id", "id", id, "error", err)
		return nil, err
	}

	// CDB returns nil data when key is not found (no error)
	if data == nil {
		return nil, ErrKeyNotFound
	}

	return data, nil
}

// Put is not supported for CDB storage as it is read-only.
// Returns ErrReadOnly.
func (s *CDBStorage) Put(ctx context.Context, key string, data []byte) error {
	slog.Warn("write operation attempted on read-only storage", "key", key)
	return ErrReadOnly
}

// Delete is not supported for CDB storage as it is read-only.
// Returns ErrReadOnly.
func (s *CDBStorage) Delete(ctx context.Context, key string) error {
	slog.Warn("delete operation attempted on read-only storage", "key", key)
	return ErrReadOnly
}

// DeleteByPrefix is not supported for CDB storage as it is read-only.
// Returns ErrReadOnly.
func (s *CDBStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	slog.Warn("delete operation attempted on read-only storage", "prefix", prefix)
	return ErrReadOnly
}

// Close closes the CDB database file.
func (s *CDBStorage) Close() error {
	if s.db == nil {
		return nil
	}

	err := s.db.Close()
	if err != nil {
		slog.Error("failed to close database", "error", err)
		return fmt.Errorf("failed to close CDB: %w", err)
	}

	return nil
}

// NewCDBStorage creates a new CDB storage instance.
// The Path in settings should be the path to a CDB file.
// Returns an error if the file cannot be opened.
func NewCDBStorage(settings Settings) (Storage, error) {
	// Get file path from params
	path, ok := settings.Params[ParamPath]
	if !ok {
		// Fallback to DSN parsing for backward compatibility
		if dsn, ok := settings.Params[ParamDSN]; ok {
			path = strings.TrimPrefix(dsn, "cdb://")
		}
	}

	if path == "" {
		slog.Error("path is required")
		return nil, fmt.Errorf("path is required for CDB storage")
	}

	db, err := cd.Open(path)
	if err != nil {
		slog.Error("failed to open CDB file", "path", path, "error", err)
		return nil, fmt.Errorf("failed to open CDB file %s: %w", path, err)
	}

	slog.Debug("CDB storage initialized", "path", path)
	return &CDBStorage{db: db, driver: settings.Driver}, nil
}

// Driver returns the driver name
func (s *CDBStorage) Driver() string {
	return s.driver
}

// ListKeys performs the list keys operation on the CDBStorage.
func (s *CDBStorage) ListKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	iter := s.db.Iter()
	var keys []string
	for iter.Next() {
		keys = append(keys, string(iter.Key()))
	}
	if err := iter.Err(); err != nil {
		slog.Error("failed to iterate CDB keys", "error", err)
		return nil, err
	}
	return keys, nil
}

// ListKeysByWorkspace performs the list keys by workspace operation on the CDBStorage.
func (s *CDBStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	iter := s.db.Iter()
	var keys []string
	for iter.Next() {
		var meta struct {
			WorkspaceID string `json:"workspace_id"`
		}
		if json.Unmarshal(iter.Value(), &meta) == nil && meta.WorkspaceID == workspaceID {
			keys = append(keys, string(iter.Key()))
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

// ValidateProxyAPIKey performs the validate proxy api key operation on the CDBStorage.
func (s *CDBStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	return nil, fmt.Errorf("ValidateProxyAPIKey not supported for cdb storage - use http storage instead")
}
