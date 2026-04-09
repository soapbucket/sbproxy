// Package storage provides pluggable storage backends for proxy configuration.
package storage

import (
	"context"
	"log/slog"
)

const DriverNoop = "noop"

type noopStorage struct{}

func (n *noopStorage) Get(_ context.Context, key string) ([]byte, error) {
	slog.Debug("noop storage get", "key", key)
	return nil, ErrKeyNotFound
}

func (n *noopStorage) GetByID(_ context.Context, id string) ([]byte, error) {
	slog.Debug("noop storage get by id", "id", id)
	return nil, ErrKeyNotFound
}

func (n *noopStorage) ListKeys(_ context.Context) ([]string, error) {
	return nil, nil
}

func (n *noopStorage) ListKeysByWorkspace(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (n *noopStorage) ValidateProxyAPIKey(_ context.Context, _ string, _ string) (*ProxyKeyValidationResult, error) {
	return nil, ErrKeyNotFound
}

func (n *noopStorage) Put(_ context.Context, _ string, _ []byte) error {
	return nil
}

func (n *noopStorage) Delete(_ context.Context, _ string) error {
	return nil
}

func (n *noopStorage) DeleteByPrefix(_ context.Context, _ string) error {
	return nil
}

func (n *noopStorage) Driver() string {
	return DriverNoop
}

func (n *noopStorage) Close() error {
	return nil
}

// NewNoopStorage creates a no-op storage that returns empty results.
func NewNoopStorage(_ Settings) (Storage, error) {
	return &noopStorage{}, nil
}

func init() {
	Register(DriverNoop, NewNoopStorage)
}
