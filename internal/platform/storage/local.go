// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var (
	localOriginsMu sync.RWMutex
	localOrigins   map[string][]byte
)

// SetLocalOrigins seeds the local storage registry. Call before NewLocalStorage.
// Pass nil to reset (useful in tests).
func SetLocalOrigins(origins map[string][]byte) {
	localOriginsMu.Lock()
	defer localOriginsMu.Unlock()
	localOrigins = origins
}

func init() {
	Register(DriverLocal, NewLocalStorage)
}

// LocalStorage is an in-memory storage backend seeded from the local origins registry.
type LocalStorage struct {
	mu      sync.RWMutex
	origins map[string][]byte
	idIndex map[string]string // id -> hostname
}

// NewLocalStorage creates and initializes a new LocalStorage.
func NewLocalStorage(_ Settings) (Storage, error) {
	localOriginsMu.RLock()
	seed := make(map[string][]byte, len(localOrigins))
	for k, v := range localOrigins {
		cp := make([]byte, len(v))
		copy(cp, v)
		seed[k] = cp
	}
	localOriginsMu.RUnlock()

	ls := &LocalStorage{
		origins: seed,
		idIndex: make(map[string]string),
	}
	for hostname, data := range seed {
		var meta struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data, &meta) == nil && meta.ID != "" {
			ls.idIndex[meta.ID] = hostname
		}
	}
	return ls, nil
}

// Get retrieves a value from the LocalStorage.
func (ls *LocalStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	data, ok := ls.origins[key]
	if !ok {
		return nil, ErrKeyNotFound
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

// GetByID returns the by id for the LocalStorage.
func (ls *LocalStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ls.mu.RLock()
	hostname, ok := ls.idIndex[id]
	ls.mu.RUnlock()
	if !ok {
		return nil, ErrKeyNotFound
	}
	return ls.Get(ctx, hostname)
}

// ListKeys performs the list keys operation on the LocalStorage.
func (ls *LocalStorage) ListKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	keys := make([]string, 0, len(ls.origins))
	for k := range ls.origins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// Put performs the put operation on the LocalStorage.
func (ls *LocalStorage) Put(ctx context.Context, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cp := make([]byte, len(data))
	copy(cp, data)

	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.origins[key] = cp

	var meta struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &meta) == nil && meta.ID != "" {
		ls.idIndex[meta.ID] = key
	}
	return nil
}

// Delete performs the delete operation on the LocalStorage.
func (ls *LocalStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	data, ok := ls.origins[key]
	if ok {
		var meta struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data, &meta) == nil && meta.ID != "" {
			delete(ls.idIndex, meta.ID)
		}
		delete(ls.origins, key)
	}
	return nil
}

// DeleteByPrefix performs the delete by prefix operation on the LocalStorage.
func (ls *LocalStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for key, data := range ls.origins {
		if strings.HasPrefix(key, prefix) {
			var meta struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(data, &meta) == nil && meta.ID != "" {
				delete(ls.idIndex, meta.ID)
			}
			delete(ls.origins, key)
		}
	}
	return nil
}

// Driver performs the driver operation on the LocalStorage.
func (ls *LocalStorage) Driver() string { return DriverLocal }
// Close releases resources held by the LocalStorage.
func (ls *LocalStorage) Close() error   { return nil }

// ListKeysByWorkspace performs the list keys by workspace operation on the LocalStorage.
func (ls *LocalStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	var keys []string
	for k, data := range ls.origins {
		var meta struct {
			WorkspaceID string `json:"workspace_id"`
		}
		if json.Unmarshal(data, &meta) == nil && meta.WorkspaceID == workspaceID {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// ValidateProxyAPIKey performs the validate proxy api key operation on the LocalStorage.
func (ls *LocalStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	return nil, fmt.Errorf("ValidateProxyAPIKey not supported for local storage - use http storage instead")
}
