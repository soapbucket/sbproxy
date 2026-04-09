// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"context"
	"io"
)

// ProxyKeyValidationResult represents a proxy key validation result.
type ProxyKeyValidationResult struct {
	ProxyKeyID   string // UUID of the ProxyAPIKey
	ProxyKeyName string // e.g., "production"
}

// StorageReader defines the interface for storage reader operations.
type StorageReader interface {
	Get(ctx context.Context, key string) ([]byte, error)
	GetByID(ctx context.Context, id string) ([]byte, error)
	ListKeys(ctx context.Context) ([]string, error)
	ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error)
	ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error)
}

// StorageWriter defines the interface for storage writer operations.
type StorageWriter interface {
	Put(ctx context.Context, key string, data []byte) error
	Delete(ctx context.Context, key string) error
	DeleteByPrefix(ctx context.Context, prefix string) error
}

// ConfigStorage defines the interface for config storage operations.
type ConfigStorage interface {
	StorageReader

	io.Closer
}

// Storage defines the interface for storage operations.
type Storage interface {
	StorageReader
	StorageWriter

	Driver() string

	io.Closer
}

// Settings holds configuration parameters for this component.
type Settings struct {
	Driver string            `json:"driver" yaml:"driver" mapstructure:"driver"`
	Params map[string]string `json:"params" yaml:"params" mapstructure:"params"`

	// Observability flags
	EnableMetrics bool `json:"enable_metrics,omitempty" yaml:"enable_metrics" mapstructure:"enable_metrics"`
	EnableTracing bool `json:"enable_tracing,omitempty" yaml:"enable_tracing" mapstructure:"enable_tracing"`
}
