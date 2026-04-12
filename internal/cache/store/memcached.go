// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
)

func init() {
	Register(DriverMemcached, NewMemcachedCacher)
}

// MemcachedCacher represents a memcached cacher.
type MemcachedCacher struct {
	client      *memcache.Client
	driver      string
	prefix      string
	maxItemSize int
}

func (m *MemcachedCacher) formatKey(cType string, key string) string {
	raw := fmt.Sprintf("%s:%s/%s", m.prefix, cType, key)
	if len(raw) <= maxMemcachedKeyLen {
		return raw
	}
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s:%s/%x", m.prefix, cType, h)
}

// Get retrieves a value from the MemcachedCacher.
func (m *MemcachedCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	slog.Debug("memcached get",
		"c_type", cType,
		"key", key)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var (
		item *memcache.Item
		done = make(chan error, 1)
	)

	go func() {
		var err error
		item, err = m.client.Get(m.formatKey(cType, key))
		done <- err
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-done:
		if err == memcache.ErrCacheMiss {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(item.Value), nil
	}
}

// Put performs the put operation on the MemcachedCacher.
func (m *MemcachedCacher) Put(ctx context.Context, cType string, key string, data io.Reader) error {
	slog.Debug("memcached put",
		"c_type", cType,
		"key", key)

	if err := ctx.Err(); err != nil {
		return err
	}

	value, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	if len(value) > m.maxItemSize {
		slog.Warn("memcached item exceeds max_item_size, skipping",
			"c_type", cType,
			"key", key,
			"size", len(value),
			"max_item_size", m.maxItemSize)
		return nil
	}

	done := make(chan error, 1)
	go func() {
		done <- m.client.Set(&memcache.Item{
			Key:   m.formatKey(cType, key),
			Value: value,
		})
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// PutWithExpires performs the put with expires operation on the MemcachedCacher.
func (m *MemcachedCacher) PutWithExpires(ctx context.Context, cType string, key string, data io.Reader, d time.Duration) error {
	slog.Debug("memcached put with expires",
		"c_type", cType,
		"key", key,
		"duration", d)

	if err := ctx.Err(); err != nil {
		return err
	}

	value, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	if len(value) > m.maxItemSize {
		slog.Warn("memcached item exceeds max_item_size, skipping",
			"c_type", cType,
			"key", key,
			"size", len(value),
			"max_item_size", m.maxItemSize)
		return nil
	}

	done := make(chan error, 1)
	go func() {
		done <- m.client.Set(&memcache.Item{
			Key:        m.formatKey(cType, key),
			Value:      value,
			Expiration: int32(d.Seconds()),
		})
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// Delete performs the delete operation on the MemcachedCacher.
func (m *MemcachedCacher) Delete(ctx context.Context, cType string, key string) error {
	slog.Debug("memcached delete",
		"c_type", cType,
		"key", key)

	if err := ctx.Err(); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		err := m.client.Delete(m.formatKey(cType, key))
		if err == memcache.ErrCacheMiss {
			err = nil
		}
		done <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// DeleteByPattern performs the delete by pattern operation on the MemcachedCacher.
func (m *MemcachedCacher) DeleteByPattern(_ context.Context, cType string, pattern string) error {
	slog.Debug("memcached delete by pattern (no-op)",
		"c_type", cType,
		"pattern", pattern)
	return nil
}

// ListKeys performs the list keys operation on the MemcachedCacher.
func (m *MemcachedCacher) ListKeys(_ context.Context, cType string, pattern string) ([]string, error) {
	slog.Debug("memcached list keys (no-op)",
		"c_type", cType,
		"pattern", pattern)
	return []string{}, nil
}

// Increment performs the increment operation on the MemcachedCacher.
func (m *MemcachedCacher) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	slog.Debug("memcached increment",
		"c_type", cType,
		"key", key,
		"count", count)

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	fkey := m.formatKey(cType, key)

	var (
		result uint64
		done   = make(chan error, 1)
	)

	go func() {
		// Seed the key if it doesn't exist. Add only succeeds if the key is missing.
		seedValue := make([]byte, 8)
		binary.LittleEndian.PutUint64(seedValue, 0)
		_ = m.client.Add(&memcache.Item{
			Key:   fkey,
			Value: seedValue,
		})

		var err error
		if count >= 0 {
			result, err = m.client.Increment(fkey, uint64(count))
		} else {
			result, err = m.client.Decrement(fkey, uint64(-count))
		}
		done <- err
	}()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case err := <-done:
		if err != nil {
			return 0, err
		}
		return int64(result), nil
	}
}

// IncrementWithExpires performs the increment with expires operation on the MemcachedCacher.
func (m *MemcachedCacher) IncrementWithExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	slog.Debug("memcached increment with expires",
		"c_type", cType,
		"key", key,
		"count", count,
		"expires", expires)

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	fkey := m.formatKey(cType, key)

	var (
		result uint64
		done   = make(chan error, 1)
	)

	go func() {
		// Seed the key with TTL if it doesn't exist.
		seedValue := make([]byte, 8)
		binary.LittleEndian.PutUint64(seedValue, 0)
		_ = m.client.Add(&memcache.Item{
			Key:        fkey,
			Value:      seedValue,
			Expiration: int32(expires.Seconds()),
		})

		var err error
		if count >= 0 {
			result, err = m.client.Increment(fkey, uint64(count))
		} else {
			result, err = m.client.Decrement(fkey, uint64(-count))
		}
		if err != nil {
			done <- err
			return
		}

		// Touch to reset TTL on every increment
		done <- m.client.Touch(fkey, int32(expires.Seconds()))
	}()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case err := <-done:
		if err != nil {
			return 0, err
		}
		return int64(result), nil
	}
}

// Close releases resources held by the MemcachedCacher.
func (m *MemcachedCacher) Close() error {
	return nil
}

// Driver performs the driver operation on the MemcachedCacher.
func (m *MemcachedCacher) Driver() string {
	return m.driver
}

// NewMemcachedCacher creates and initializes a new MemcachedCacher.
func NewMemcachedCacher(settings Settings) (Cacher, error) {
	servers, ok := settings.Params[SettingServers]
	if !ok || servers == "" {
		return nil, ErrInvalidConfiguration
	}

	prefix := defaultPrefix
	if p, ok := settings.Params[SettingPrefix]; ok && p != "" {
		prefix = p
	}

	maxItemSize := defaultMaxItemSize
	if v, ok := settings.Params[SettingMaxItemSize]; ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid max_item_size parameter: %w", err)
		}
		maxItemSize = parsed
	}

	connectTimeout := defaultConnectTimeout
	if v, ok := settings.Params[SettingConnectTimeout]; ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid connect_timeout parameter: %w", err)
		}
		connectTimeout = parsed
	}

	timeout := defaultTimeout
	if v, ok := settings.Params[SettingTimeout]; ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout parameter: %w", err)
		}
		timeout = parsed
	}

	maxIdleConns := defaultMaxIdleConns
	if v, ok := settings.Params[SettingMaxIdleConns]; ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid max_idle_conns parameter: %w", err)
		}
		maxIdleConns = parsed
	}

	serverList := strings.Split(servers, ",")
	for i := range serverList {
		serverList[i] = strings.TrimSpace(serverList[i])
	}

	slog.Debug("opening memcached connection",
		"servers", serverList,
		"prefix", prefix,
		"max_item_size", maxItemSize)

	client := memcache.New(serverList...)
	// gomemcache uses a single Timeout for both connect and read/write.
	// Use the larger of connect_timeout and timeout to cover both.
	effectiveTimeout := connectTimeout
	if timeout > effectiveTimeout {
		effectiveTimeout = timeout
	}
	client.Timeout = time.Duration(effectiveTimeout) * time.Millisecond
	client.MaxIdleConns = maxIdleConns

	return &MemcachedCacher{
		client:      client,
		driver:      settings.Driver,
		prefix:      prefix,
		maxItemSize: maxItemSize,
	}, nil
}
