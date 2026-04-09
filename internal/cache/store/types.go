// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"context"
	"io"
	"time"
)

// Settings holds configuration parameters for this component.
type Settings struct {
	Driver     string            `json:"driver" yaml:"driver" mapstructure:"driver"`
	MaxObjects int               `json:"max_objects" yaml:"max_objects" mapstructure:"max_objects"`
	MaxMemory  int64             `json:"max_memory" yaml:"max_memory" mapstructure:"max_memory"`
	Params     map[string]string `json:"params" yaml:"params" mapstructure:"params"`

	// Observability flags
	EnableMetrics bool `json:"enable_metrics,omitempty" yaml:"enable_metrics" mapstructure:"enable_metrics"`
	EnableTracing bool `json:"enable_tracing,omitempty" yaml:"enable_tracing" mapstructure:"enable_tracing"`
}

// Counter defines the interface for counter operations.
type Counter interface {
	Increment(context.Context, string, string, int64) (int64, error)
	IncrementWithExpires(context.Context, string, string, int64, time.Duration) (int64, error)
}

// Reader defines the interface for reader operations.
type Reader interface {
	Get(context.Context, string, string) (io.Reader, error)
	ListKeys(context.Context, string, string) ([]string, error)
}

// Writer defines the interface for writer operations.
type Writer interface {
	Put(context.Context, string, string, io.Reader) error
	PutWithExpires(context.Context, string, string, io.Reader, time.Duration) error
	Delete(context.Context, string, string) error
	DeleteByPattern(context.Context, string, string) error
}

// ReadWriter defines the interface for read writer operations.
type ReadWriter interface {
	Reader
	Writer
}

// Cacher defines the interface for cacher operations.
type Cacher interface {
	ReadWriter
	Counter

	Driver() string

	io.Closer
}
