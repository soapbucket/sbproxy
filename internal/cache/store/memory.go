// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/object"
)

func init() {
	Register(DriverMemory, NewMemoryCacher)
}

// MemoryCacher represents a memory cacher.
type MemoryCacher struct {
	manager *objectcache.ObjectCache
	driver  string
}

// Close releases resources held by the MemoryCacher.
func (m *MemoryCacher) Close() error {
	return m.manager.Close()
}

// makeKey builds a composite cache key without allocating an intermediate string.
// It writes cType + "/" + key directly into a strings.Builder.
func makeKey(cType, key string) string {
	var b strings.Builder
	b.Grow(len(cType) + 1 + len(key))
	b.WriteString(cType)
	b.WriteByte('/')
	b.WriteString(key)
	return b.String()
}

// Get retrieves a value from the MemoryCacher.
func (m *MemoryCacher) Get(ctx context.Context, cType string, key string) (io.Reader, error) {
	fullKey := makeKey(cType, key)
	value, ok := m.manager.Get(fullKey)
	if !ok {
		return nil, ErrNotFound
	}

	// Handle different value types
	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case int64:
		data = []byte(strconv.FormatInt(v, 10))
	case int:
		data = []byte(strconv.Itoa(v))
	case string:
		data = []byte(v)
	default:
		data = []byte(fmt.Sprintf("%v", v))
	}

	return bytes.NewReader(data), nil
}

// Put performs the put operation on the MemoryCacher.
func (m *MemoryCacher) Put(ctx context.Context, cType string, key string, value io.Reader) error {
	fullKey := makeKey(cType, key)
	data, err := io.ReadAll(value)
	if err != nil {

		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	m.manager.Put(fullKey, data)

	return nil
}

// PutWithExpires performs the put with expires operation on the MemoryCacher.
func (m *MemoryCacher) PutWithExpires(ctx context.Context, cType string, key string, value io.Reader, expires time.Duration) error {
	fullKey := makeKey(cType, key)
	data, err := io.ReadAll(value)
	if err != nil {
		return fmt.Errorf("failed to read from io.Reader: %w", err)
	}

	m.manager.PutWithExpires(fullKey, data, expires)
	return nil
}

// Delete performs the delete operation on the MemoryCacher.
func (m *MemoryCacher) Delete(ctx context.Context, cType string, key string) error {
	fullKey := makeKey(cType, key)
	m.manager.Delete(fullKey)
	return nil
}

// Increment performs the increment operation on the MemoryCacher.
func (m *MemoryCacher) Increment(ctx context.Context, cType string, key string, count int64) (int64, error) {
	fullKey := makeKey(cType, key)
	return m.manager.Increment(fullKey, count), nil
}

// IncrementWithExpires performs the increment with expires operation on the MemoryCacher.
func (m *MemoryCacher) IncrementWithExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error) {
	fullKey := makeKey(cType, key)
	return m.manager.IncrementWithExpires(fullKey, count, expires), nil
}

// DeleteByPattern performs the delete by pattern operation on the MemoryCacher.
func (m *MemoryCacher) DeleteByPattern(ctx context.Context, cType string, pattern string) error {
	fullKey := makeKey(cType, pattern)
	m.manager.DeleteByPrefix(fullKey)
	return nil
}

// ListKeys performs the list keys operation on the MemoryCacher.
func (m *MemoryCacher) ListKeys(ctx context.Context, cType string, pattern string) ([]string, error) {
	fullPrefix := makeKey(cType, pattern)
	allKeys := m.manager.GetKeysByPrefix(fullPrefix)

	// Remove the cType prefix from keys and extract just the key part
	prefixToRemove := cType + "/"
	keys := make([]string, 0, len(allKeys))
	for _, fullKey := range allKeys {
		if strings.HasPrefix(fullKey, prefixToRemove) {
			key := strings.TrimPrefix(fullKey, prefixToRemove)
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// NewMemoryCacher creates and initializes a new MemoryCacher.
func NewMemoryCacher(settings Settings) (Cacher, error) {
	var err error

	// Parse duration (default expiration time for entries)
	var expireInterval time.Duration
	duration, ok := settings.Params[SettingDuration]
	if ok {
		expireInterval, err = time.ParseDuration(duration)
		if err != nil {
			return nil, fmt.Errorf("invalid duration parameter: %w", err)
		}
	} else {
		expireInterval = defaultExpireInterval
	}

	// Parse cleanup interval
	var cleanupInterval time.Duration
	cleanup, ok := settings.Params[SettingCleanupInterval]
	if ok {
		cleanupInterval, err = time.ParseDuration(cleanup)
		if err != nil {
			return nil, fmt.Errorf("invalid cleanup_interval parameter: %w", err)
		}
	} else {
		cleanupInterval = defaultCleanupInterval
	}

	// Parse capacity (currently not enforced, but available for future use)
	capacity := defaultCapacity
	if capacityStr, ok := settings.Params[SettingCapacity]; ok {
		if _, err := fmt.Sscanf(capacityStr, "%d", &capacity); err != nil {
			return nil, fmt.Errorf("invalid capacity parameter: %w", err)
		}
	}

	// Parse max_objects (0 means unlimited)
	maxObjects := 0
	if maxObjectsStr, ok := settings.Params[SettingMaxObjects]; ok {
		maxObjects, err = strconv.Atoi(maxObjectsStr)
		if err != nil {
			return nil, fmt.Errorf("invalid max_objects parameter: %w", err)
		}
	}

	// Parse max_memory (0 means unlimited, supports suffixes like MB, GB)
	maxMemory := int64(0)
	if maxMemoryStr, ok := settings.Params[SettingMaxMemory]; ok {
		maxMemory, err = parseMemorySize(maxMemoryStr)
		if err != nil {
			return nil, fmt.Errorf("invalid max_memory parameter: %w", err)
		}
	}

	manager, err := objectcache.NewObjectCache(expireInterval, cleanupInterval, maxObjects, maxMemory)
	if err != nil {
		return nil, err
	}

	slog.Debug("created memory cacher", "duration", expireInterval, "cleanup_interval", cleanupInterval, "capacity", capacity, "max_objects", maxObjects, "max_memory", maxMemory)

	return &MemoryCacher{
		manager: manager,
		driver:  settings.Driver,
	}, nil
}

// parseMemorySize parses memory size strings like "100MB", "1GB", "500KB"
func parseMemorySize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(sizeStr)
	if sizeStr == "" {
		return 0, nil
	}

	// Extract number and unit
	var numStr string
	var unit string

	for i, char := range sizeStr {
		if char >= '0' && char <= '9' {
			numStr += string(char)
		} else {
			unit = sizeStr[i:]
			break
		}
	}

	if numStr == "" {
		return 0, fmt.Errorf("no number found in memory size: %s", sizeStr)
	}

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in memory size: %s", numStr)
	}

	// Convert unit to bytes
	const maxMemorySize int64 = 1 << 40 // 1TB upper bound

	unit = strings.ToUpper(unit)
	var result int64
	switch unit {
	case "", "B":
		result = num
	case "KB":
		result = num * 1024
	case "MB":
		result = num * 1024 * 1024
	case "GB":
		result = num * 1024 * 1024 * 1024
	case "TB":
		result = num * 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unsupported memory unit: %s", unit)
	}

	if result > maxMemorySize {
		return 0, fmt.Errorf("memory size exceeds maximum allowed (1TB)")
	}

	return result, nil
}

// Driver returns the driver name
func (m *MemoryCacher) Driver() string {
	return m.driver
}
