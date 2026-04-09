// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

func init() {
	Register(DriverFile, NewFileStorage)
}

// FileStorage implements ConfigStorage interface for file-based storage
type FileStorage struct {
	filePath string
	data     map[string]interface{}
	mu       sync.RWMutex
	driver   string
}

// Get retrieves data by key and returns it as JSON bytes
func (fs *FileStorage) Get(ctx context.Context, key string) ([]byte, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return nil, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	value, exists := fs.data[key]
	if !exists {
		slog.Debug("key not found", "key", key)
		return nil, ErrKeyNotFound
	}

	// Convert the value to JSON bytes
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		slog.Error("failed to marshal value", "key", key, "error", err)
		return nil, fmt.Errorf("failed to marshal value for key '%s': %w", key, err)
	}

	return jsonBytes, nil
}

// GetByID retrieves data by ID (same as Get for this implementation)
func (fs *FileStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		slog.Error("context cancelled", "error", err)
		return nil, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	value, exists := fs.data[id]
	if !exists {
		slog.Debug("id not found", "id", id)
		return nil, ErrKeyNotFound
	}

	// Convert the value to JSON bytes
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		slog.Error("failed to marshal value", "id", id, "error", err)
		return nil, fmt.Errorf("failed to marshal value for id '%s': %w", id, err)
	}

	return jsonBytes, nil
}

// Put is not supported for file storage as it is read-only.
// Returns ErrReadOnly.
func (fs *FileStorage) Put(ctx context.Context, key string, data []byte) error {
	slog.Warn("write operation attempted on read-only storage", "key", key)
	return ErrReadOnly
}

// Delete is not supported for file storage as it is read-only.
// Returns ErrReadOnly.
func (fs *FileStorage) Delete(ctx context.Context, key string) error {
	slog.Warn("delete operation attempted on read-only storage", "key", key)
	return ErrReadOnly
}

// DeleteByPrefix is not supported for file storage as it is read-only.
// Returns ErrReadOnly.
func (fs *FileStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	slog.Warn("delete operation attempted on read-only storage", "prefix", prefix)
	return ErrReadOnly
}

// Close implements io.Closer interface
func (fs *FileStorage) Close() error {
	// For read-only file storage, there's nothing to close
	// The file was only opened during loadData and is already closed
	return nil
}

// Driver returns the driver name
func (fs *FileStorage) Driver() string {
	return fs.driver
}

// ListKeys performs the list keys operation on the FileStorage.
func (fs *FileStorage) ListKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	keys := make([]string, 0, len(fs.data))
	for k := range fs.data {
		keys = append(keys, k)
	}
	return keys, nil
}

// ListKeysByWorkspace performs the list keys by workspace operation on the FileStorage.
func (fs *FileStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var keys []string
	for k, v := range fs.data {
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			continue
		}
		var meta struct {
			WorkspaceID string `json:"workspace_id"`
		}
		if json.Unmarshal(jsonBytes, &meta) == nil && meta.WorkspaceID == workspaceID {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// ValidateProxyAPIKey performs the validate proxy api key operation on the FileStorage.
func (fs *FileStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	return nil, fmt.Errorf("ValidateProxyAPIKey not supported for file storage - use http storage instead")
}

// loadData loads the origins file (JSON or YAML) into the internal map.
// Files with extension .yml or .yaml are decoded as YAML; otherwise JSON is used.
func (fs *FileStorage) loadData() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	slog.Debug("loading file", "file_path", fs.filePath)
	raw, err := os.ReadFile(fs.filePath)
	if err != nil {
		slog.Error("failed to read file", "error", err, "file_path", fs.filePath)
		return fmt.Errorf("failed to read file: %w", err)
	}

	lower := strings.ToLower(fs.filePath)
	if strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") {
		if err := yaml.Unmarshal(raw, &fs.data); err != nil {
			return fmt.Errorf("failed to decode YAML: %w", err)
		}
	} else {
		if err := json.Unmarshal(raw, &fs.data); err != nil {
			return fmt.Errorf("failed to decode JSON: %w", err)
		}
	}

	slog.Debug("file loaded", "file_path", fs.filePath, "num_keys", len(fs.data))

	return nil
}

// NewFileStorage creates a new file storage instance.
// The path param may point to a .json, .yml, or .yaml file (format is inferred from extension).
// Returns an error if the file cannot be opened or parsed.
func NewFileStorage(settings Settings) (Storage, error) {
	// Get file path from params
	path := settings.Params[ParamPath]

	slog.Debug("initializing file storage", "file_path", path)

	if path == "" {
		slog.Error("file path is required")
		return nil, fmt.Errorf("file path is required for file storage")
	}

	fs := &FileStorage{
		filePath: path,
		data:     make(map[string]interface{}),
		driver:   settings.Driver,
	}

	if err := fs.loadData(); err != nil {
		slog.Error("failed to load data from file", "file_path", path, "error", err)
		return nil, fmt.Errorf("failed to load data from file %s: %w", path, err)
	}

	slog.Debug("file storage initialized", "file_path", path)
	return fs, nil
}
