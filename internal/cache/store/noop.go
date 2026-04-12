// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"context"
	"io"
	"log/slog"
	"time"
)

func init() {
	Register(DriverNoop, func(Settings) (Cacher, error) {
		return Noop, nil
	})
}

// Noop is a variable for noop.
var Noop Cacher = noop{}

type noop struct{}

// Close releases resources held by the noop.
func (noop) Close() error {
	slog.Debug("closing noop cacher")
	return nil
}

// Delete performs the delete operation on the noop.
func (noop) Delete(_ context.Context, cType string, key string) error {
	slog.Debug("deleting noop cacher", "c_type", cType, "key", key)
	return nil
}

// DeleteByPattern performs the delete by pattern operation on the noop.
func (noop) DeleteByPattern(_ context.Context, cType string, pattern string) error {
	slog.Debug("deleting noop cacher by pattern", "c_type", cType, "pattern", pattern)
	return nil
}

// Get retrieves a value from the noop.
func (noop) Get(_ context.Context, cType string, key string) (io.Reader, error) {
	slog.Debug("getting noop cacher", "c_type", cType, "key", key)
	return nil, ErrNotFound
}

// ListKeys performs the list keys operation on the noop.
func (noop) ListKeys(_ context.Context, cType string, pattern string) ([]string, error) {
	slog.Debug("listing keys noop cacher", "c_type", cType, "pattern", pattern)
	return []string{}, nil
}

// Put performs the put operation on the noop.
func (noop) Put(_ context.Context, cType string, key string, _ io.Reader) error {
	slog.Debug("putting noop cacher", "c_type", cType, "key", key)
	return nil
}

// PutWithExpires performs the put with expires operation on the noop.
func (noop) PutWithExpires(_ context.Context, cType string, key string, _ io.Reader, expires time.Duration) error {
	slog.Debug("putting noop cacher with expires", "c_type", cType, "key", key, "expires", expires)
	return nil
}

// Increment performs the increment operation on the noop.
func (noop) Increment(_ context.Context, cType string, key string, count int64) (int64, error) {
	slog.Debug("incrementing noop cacher", "c_type", cType, "key", key, "count", count)
	return count, nil
}

// IncrementWithExpires performs the increment with expires operation on the noop.
func (noop) IncrementWithExpires(_ context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	slog.Debug("incrementing noop cacher with expires", "c_type", cType, "key", key, "count", count, "expires", expires)
	return count, nil
}

// Driver returns the driver name
func (noop) Driver() string {
	return DriverNoop
}
