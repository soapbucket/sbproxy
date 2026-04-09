// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

func init() {
	Register(DriverRedis, NewRedisCacher)
}

// RedisCacher represents a redis cacher.
type RedisCacher struct {
	db     *redis.Client
	driver string
}

// Get retrieves a value from the RedisCacher.
func (r *RedisCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	slog.Debug("get",
		"c_type", cType,
		"key", key)

	switch value, err := r.db.HGet(ctx, cType, key).Bytes(); {
	case err == redis.Nil:

		return nil, ErrNotFound
	case err != nil:

		return nil, err
	default:

		return bytes.NewReader(value), err
	}
}

// Put performs the put operation on the RedisCacher.
func (r *RedisCacher) Put(ctx context.Context, cType string, key string, data io.Reader) error {
	slog.Debug("put",
		"c_type", cType,
		"key", key)

	bytes, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	err = r.db.HSet(ctx, cType, key, bytes).Err()
	if err != nil {
		return err
	}

	return nil
}

// PutWithExpires performs the put with expires operation on the RedisCacher.
func (r *RedisCacher) PutWithExpires(ctx context.Context, cType string, key string, data io.Reader, d time.Duration) error {
	slog.Debug("put with expires",
		"c_type", cType,
		"key", key,
		"duration", d)

	bytes, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	err = r.db.HSet(ctx, cType, key, bytes).Err()
	if err != nil {
		return err
	}
	err = r.db.HExpire(ctx, cType, d, key).Err()
	if err != nil {
		return err
	}

	return nil
}

// DeleteByPattern performs the delete by pattern operation on the RedisCacher.
func (r *RedisCacher) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	slog.Debug("delete by pattern",
		"c_type", cType,
		"pattern", pattern)

	// Use HScan for cursor-based iteration instead of HKeys to avoid loading
	// all hash keys into memory at once (scalability for large hashes).
	var keysToDelete []string
	var cursor uint64
	for {
		keys, nextCursor, err := r.db.HScan(ctx, cType, cursor, "", 100).Result()
		if err != nil {
			return err
		}
		// HScan returns alternating key, value pairs
		for i := 0; i < len(keys); i += 2 {
			key := keys[i]
			if matched, _ := matchPattern(key, pattern); matched {
				keysToDelete = append(keysToDelete, key)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	if len(keysToDelete) > 0 {
		return r.db.HDel(ctx, cType, keysToDelete...).Err()
	}
	return nil
}

// Delete performs the delete operation on the RedisCacher.
func (r *RedisCacher) Delete(ctx context.Context, cType string, key string) error {
	slog.Debug("delete",
		"c_type", cType,
		"key", key)
	err := r.db.HDel(ctx, cType, key).Err()
	if err != nil {
		return err
	}
	return nil
}

// Increment performs the increment operation on the RedisCacher.
func (m *RedisCacher) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	slog.Debug("increment",
		"c_type", cType,
		"key", key,
		"count", count)
	return m.db.HIncrBy(ctx, cType, key, count).Result()
}

// IncrementWithExpires performs the increment with expires operation on the RedisCacher.
func (m *RedisCacher) IncrementWithExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	slog.Debug("increment with expires",
		"c_type", cType,
		"key", key,
		"count", count,
		"expires", expires)
	value, err := m.db.HIncrBy(ctx, cType, key, count).Result()
	if err != nil {
		return 0, err
	}
	err = m.db.HExpire(ctx, cType, expires, key).Err()
	if err != nil {
		return 0, err
	}
	return value, err
}


// ListKeys performs the list keys operation on the RedisCacher.
func (r *RedisCacher) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	slog.Debug("list keys",
		"c_type", cType,
		"pattern", pattern)

	// Use HScan for cursor-based iteration instead of HKeys
	var matchingKeys []string
	var cursor uint64
	for {
		keys, nextCursor, err := r.db.HScan(ctx, cType, cursor, "", 100).Result()
		if err != nil {
			return nil, err
		}
		// HScan returns alternating key, value pairs
		for i := 0; i < len(keys); i += 2 {
			key := keys[i]
			if matched, _ := matchPattern(key, pattern); matched {
				matchingKeys = append(matchingKeys, key)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return matchingKeys, nil
}

// Close releases resources held by the RedisCacher.
func (r *RedisCacher) Close() error {
	return r.db.Close()
}

// Driver returns the driver name
func (r *RedisCacher) Driver() string {
	return r.driver
}

// NewRedisCacher creates and initializes a new RedisCacher.
func NewRedisCacher(settings Settings) (Cacher, error) {
	dsn, ok := settings.Params[ParamDSN]
	if !ok {
		return nil, ErrInvalidConfiguration
	}

	slog.Debug("opening connection",
		"dsn", dsn)
	options, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, err
	}

	// Optimize connection pool for high throughput (per OPTIMIZATIONS.md #24)
	// Default values optimized for high-throughput scenarios
	options.PoolSize = getIntParam(settings.Params, "pool_size", 200)                // Max number of socket connections (increased from 100)
	options.MinIdleConns = getIntParam(settings.Params, "min_idle_conns", 20)      // Minimum number of idle connections (increased from 10)
	options.PoolTimeout = getDurationParam(settings.Params, "pool_timeout", 10*time.Second) // Amount of time client waits for connection (increased from 4s)

	// Performance tuning
	options.MaxRetries = getIntParam(settings.Params, "max_retries", 5) // Increased from 3
	options.MinRetryBackoff = 8 * time.Millisecond
	options.MaxRetryBackoff = 512 * time.Millisecond
	options.DialTimeout = 5 * time.Second
	options.ReadTimeout = getDurationParam(settings.Params, "read_timeout", 5*time.Second)   // Increased from 3s
	options.WriteTimeout = getDurationParam(settings.Params, "write_timeout", 5*time.Second)  // Increased from 3s

	rdb := redis.NewClient(options)
	return &RedisCacher{db: rdb, driver: settings.Driver}, nil
}

// getIntParam retrieves an integer parameter from settings, returning default if not found or invalid
func getIntParam(params map[string]string, key string, defaultValue int) int {
	if val, ok := params[key]; ok {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getDurationParam retrieves a duration parameter from settings, returning default if not found or invalid
func getDurationParam(params map[string]string, key string, defaultValue time.Duration) time.Duration {
	if val, ok := params[key]; ok {
		if duration, err := time.ParseDuration(val); err == nil {
			return duration
		}
	}
	return defaultValue
}
