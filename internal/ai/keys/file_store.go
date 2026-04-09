package keys

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// ErrReadOnly is returned when a write operation is attempted on a read-only store.
var ErrReadOnly = fmt.Errorf("store is read-only")

// fileKeyEntry is the on-disk format for a virtual key definition.
// It includes RawKey for hashing on load (never stored in memory after hashing).
type fileKeyEntry struct {
	VirtualKey
	RawKey string `json:"raw_key,omitempty"` // Hashed on load, then cleared
}

// fileKeyFile is the top-level JSON structure for the key definitions file.
type fileKeyFile struct {
	Keys []fileKeyEntry `json:"keys"`
}

// FileStore is a read-only virtual key store backed by a JSON file.
// Keys are loaded at startup and reloaded when the file changes.
// Write operations return ErrReadOnly.
type FileStore struct {
	mu      sync.RWMutex
	path    string
	byID    map[string]*VirtualKey
	byHash  map[string]*VirtualKey
	modTime time.Time
}

// NewFileStore creates a new file-backed virtual key store.
// The file is read immediately; an error is returned if the file cannot be loaded.
func NewFileStore(path string) (*FileStore, error) {
	fs := &FileStore{
		path:   path,
		byID:   make(map[string]*VirtualKey),
		byHash: make(map[string]*VirtualKey),
	}
	if err := fs.load(); err != nil {
		return nil, fmt.Errorf("failed to load key file %s: %w", path, err)
	}
	return fs, nil
}

// load reads and parses the key definitions file.
func (fs *FileStore) load() error {
	data, err := os.ReadFile(fs.path)
	if err != nil {
		return err
	}

	info, err := os.Stat(fs.path)
	if err != nil {
		return err
	}

	var kf fileKeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return fmt.Errorf("invalid JSON in %s: %w", fs.path, err)
	}

	byID := make(map[string]*VirtualKey, len(kf.Keys))
	byHash := make(map[string]*VirtualKey, len(kf.Keys))

	for _, entry := range kf.Keys {
		vk := entry.VirtualKey

		// Hash the raw key if provided
		if entry.RawKey != "" {
			vk.HashedKey = HashKey(entry.RawKey)
		}
		if vk.HashedKey == "" {
			slog.Warn("virtual key has no raw_key or hashed_key, skipping", "id", vk.ID)
			continue
		}
		if vk.ID == "" {
			slog.Warn("virtual key has no id, skipping", "hashed_key", vk.HashedKey[:8]+"...")
			continue
		}
		if vk.Status == "" {
			vk.Status = "active"
		}

		cp := vk
		byID[vk.ID] = &cp
		byHash[vk.HashedKey] = &cp
	}

	fs.mu.Lock()
	fs.byID = byID
	fs.byHash = byHash
	fs.modTime = info.ModTime()
	fs.mu.Unlock()

	slog.Info("loaded virtual keys from file", "path", fs.path, "count", len(byID))
	return nil
}

// Reload re-reads the key file, replacing all in-memory keys.
func (fs *FileStore) Reload() error {
	return fs.load()
}

// WatchFile polls the key file for changes and reloads when modified.
// Call in a goroutine: go fs.WatchFile(ctx)
func (fs *FileStore) WatchFile(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(fs.path)
			if err != nil {
				continue
			}
			fs.mu.RLock()
			changed := info.ModTime().After(fs.modTime)
			fs.mu.RUnlock()

			if changed {
				if err := fs.Reload(); err != nil {
					slog.Error("failed to reload virtual keys file", "path", fs.path, "error", err)
				}
			}
		}
	}
}

// GetByHash retrieves a virtual key by its hashed value.
func (fs *FileStore) GetByHash(_ context.Context, hashedKey string) (*VirtualKey, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	vk, ok := fs.byHash[hashedKey]
	if !ok {
		return nil, ErrKeyNotFound
	}
	cp := *vk
	return &cp, nil
}

// GetByID retrieves a virtual key by its ID.
func (fs *FileStore) GetByID(_ context.Context, id string) (*VirtualKey, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	vk, ok := fs.byID[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	cp := *vk
	return &cp, nil
}

// List returns virtual keys for a workspace, filtered by opts.
func (fs *FileStore) List(_ context.Context, workspaceID string, opts ListOpts) ([]*VirtualKey, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var result []*VirtualKey
	for _, vk := range fs.byID {
		if workspaceID != "" && vk.WorkspaceID != workspaceID {
			continue
		}
		if opts.Status != "" && vk.Status != opts.Status {
			continue
		}
		cp := *vk
		result = append(result, &cp)
	}

	if opts.Offset > 0 {
		if opts.Offset >= len(result) {
			return nil, nil
		}
		result = result[opts.Offset:]
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}

	return result, nil
}

// Create is not supported on a read-only file store.
func (fs *FileStore) Create(_ context.Context, _ *VirtualKey) error {
	return ErrReadOnly
}

// Update is not supported on a read-only file store.
func (fs *FileStore) Update(_ context.Context, _ string, _ map[string]any) error {
	return ErrReadOnly
}

// Revoke is not supported on a read-only file store.
func (fs *FileStore) Revoke(_ context.Context, _ string) error {
	return ErrReadOnly
}

// Delete is not supported on a read-only file store.
func (fs *FileStore) Delete(_ context.Context, _ string) error {
	return ErrReadOnly
}
