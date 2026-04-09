// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

func init() {
	Register(DriverComposite, NewCompositeStorage)
}

// CompositeStorage reads from primary (LocalStorage) first, falls back to secondary.
type CompositeStorage struct {
	primary   Storage
	secondary Storage
}

// NewCompositeStorage creates and initializes a new CompositeStorage.
func NewCompositeStorage(settings Settings) (Storage, error) {
	primary, err := NewLocalStorage(settings)
	if err != nil {
		return nil, fmt.Errorf("composite: create local primary: %w", err)
	}

	secondaryDriver := settings.Params["secondary_driver"]
	if secondaryDriver == "" {
		return primary, nil // local-only mode
	}

	secondaryParams := make(map[string]string)
	const pfx = "secondary_"
	for k, v := range settings.Params {
		if strings.HasPrefix(k, pfx) && k != "secondary_driver" {
			secondaryParams[strings.TrimPrefix(k, pfx)] = v
		}
	}

	secondary, err := NewStorage(Settings{Driver: secondaryDriver, Params: secondaryParams})
	if err != nil {
		return nil, fmt.Errorf("composite: create secondary %q: %w", secondaryDriver, err)
	}

	return &CompositeStorage{primary: primary, secondary: secondary}, nil
}

// Get retrieves a value from the CompositeStorage.
func (cs *CompositeStorage) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := cs.primary.Get(ctx, key)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	return cs.secondary.Get(ctx, key)
}

// GetByID returns the by id for the CompositeStorage.
func (cs *CompositeStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	data, err := cs.primary.GetByID(ctx, id)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	return cs.secondary.GetByID(ctx, id)
}

// ListKeys performs the list keys operation on the CompositeStorage.
func (cs *CompositeStorage) ListKeys(ctx context.Context) ([]string, error) {
	primaryKeys, err := cs.primary.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	secondaryKeys, err := cs.secondary.ListKeys(ctx)
	if err != nil && !errors.Is(err, ErrListKeysNotSupported) {
		return nil, err
	}
	seen := make(map[string]struct{}, len(primaryKeys)+len(secondaryKeys))
	for _, k := range primaryKeys {
		seen[k] = struct{}{}
	}
	result := append([]string{}, primaryKeys...)
	for _, k := range secondaryKeys {
		if _, ok := seen[k]; !ok {
			result = append(result, k)
		}
	}
	sort.Strings(result)
	return result, nil
}

// Put performs the put operation on the CompositeStorage.
func (cs *CompositeStorage) Put(ctx context.Context, key string, data []byte) error {
	if err := cs.primary.Put(ctx, key, data); err != nil {
		return err
	}
	if err := cs.secondary.Put(ctx, key, data); err != nil && !errors.Is(err, ErrReadOnly) {
		return err
	}
	return nil
}

// Delete performs the delete operation on the CompositeStorage.
func (cs *CompositeStorage) Delete(ctx context.Context, key string) error {
	if err := cs.primary.Delete(ctx, key); err != nil {
		return err
	}
	if err := cs.secondary.Delete(ctx, key); err != nil && !errors.Is(err, ErrReadOnly) {
		return err
	}
	return nil
}

// DeleteByPrefix performs the delete by prefix operation on the CompositeStorage.
func (cs *CompositeStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	if err := cs.primary.DeleteByPrefix(ctx, prefix); err != nil {
		return err
	}
	if err := cs.secondary.DeleteByPrefix(ctx, prefix); err != nil && !errors.Is(err, ErrReadOnly) {
		return err
	}
	return nil
}

// Driver performs the driver operation on the CompositeStorage.
func (cs *CompositeStorage) Driver() string { return DriverComposite }

// Close releases resources held by the CompositeStorage.
func (cs *CompositeStorage) Close() error {
	pErr := cs.primary.Close()
	sErr := cs.secondary.Close()
	if pErr != nil && sErr != nil {
		return fmt.Errorf("composite close: primary: %w; secondary: %v", pErr, sErr)
	}
	if pErr != nil {
		return fmt.Errorf("composite close: primary: %w", pErr)
	}
	return sErr
}

// ListKeysByWorkspace performs the list keys by workspace operation on the CompositeStorage.
func (cs *CompositeStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	primaryKeys, err := cs.primary.ListKeysByWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	secondaryKeys, err := cs.secondary.ListKeysByWorkspace(ctx, workspaceID)
	if err != nil && !errors.Is(err, ErrListKeysNotSupported) {
		return nil, err
	}
	seen := make(map[string]struct{}, len(primaryKeys)+len(secondaryKeys))
	for _, k := range primaryKeys {
		seen[k] = struct{}{}
	}
	result := append([]string{}, primaryKeys...)
	for _, k := range secondaryKeys {
		if _, ok := seen[k]; !ok {
			result = append(result, k)
		}
	}
	sort.Strings(result)
	return result, nil
}

// ValidateProxyAPIKey performs the validate proxy api key operation on the CompositeStorage.
func (cs *CompositeStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	result, err := cs.primary.ValidateProxyAPIKey(ctx, originID, apiKey)
	if err == nil {
		return result, nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	return cs.secondary.ValidateProxyAPIKey(ctx, originID, apiKey)
}
