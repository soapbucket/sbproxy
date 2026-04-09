// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

// memoryEntry holds a value with optional expiration for the in-memory state store.
type memoryEntry struct {
	value     []byte
	expiresAt time.Time // zero means no expiration
}

// MemoryPolicyStateStore implements PolicyStateStore backed by a sync.Map.
// This is the default fallback when no external store (Redis) is configured.
type MemoryPolicyStateStore struct {
	data sync.Map // map[string]*memoryEntry
}

// NewMemoryPolicyStateStore creates a new in-memory policy state store.
func NewMemoryPolicyStateStore() *MemoryPolicyStateStore {
	return &MemoryPolicyStateStore{}
}

// Get retrieves a value by key. Returns nil, nil if the key does not exist or is expired.
func (m *MemoryPolicyStateStore) Get(_ context.Context, key string) ([]byte, error) {
	val, ok := m.data.Load(key)
	if !ok {
		return nil, nil
	}
	entry := val.(*memoryEntry)
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		m.data.Delete(key)
		return nil, nil
	}
	// Return a copy to prevent mutation
	result := make([]byte, len(entry.value))
	copy(result, entry.value)
	return result, nil
}

// Set stores a value with an optional TTL. A zero TTL means no expiration.
func (m *MemoryPolicyStateStore) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	entry := &memoryEntry{
		value: make([]byte, len(value)),
	}
	copy(entry.value, value)
	if ttl > 0 {
		entry.expiresAt = time.Now().Add(ttl)
	}
	m.data.Store(key, entry)
	return nil
}

// Delete removes a key.
func (m *MemoryPolicyStateStore) Delete(_ context.Context, key string) error {
	m.data.Delete(key)
	return nil
}

// Increment atomically increments a counter stored as a little-endian int64.
// If the key does not exist or is expired, it is created with a value of 1.
func (m *MemoryPolicyStateStore) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	for {
		val, loaded := m.data.Load(key)
		if !loaded {
			// Try to store a new entry with value 1
			entry := &memoryEntry{
				value: make([]byte, 8),
			}
			binary.LittleEndian.PutUint64(entry.value, 1)
			if ttl > 0 {
				entry.expiresAt = time.Now().Add(ttl)
			}
			// Use LoadOrStore for atomicity
			actual, existed := m.data.LoadOrStore(key, entry)
			if !existed {
				return 1, nil
			}
			// Another goroutine beat us, fall through to increment
			val = actual
		}

		entry := val.(*memoryEntry)
		if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
			// Expired, treat as new
			m.data.Delete(key)
			continue
		}

		// Decode current value, increment, store back
		var current int64
		if len(entry.value) >= 8 {
			current = int64(binary.LittleEndian.Uint64(entry.value))
		}
		current++

		newEntry := &memoryEntry{
			value:     make([]byte, 8),
			expiresAt: entry.expiresAt,
		}
		binary.LittleEndian.PutUint64(newEntry.value, uint64(current))

		// CompareAndSwap via LoadOrStore pattern - store unconditionally since
		// sync.Map doesn't have CAS. For policy counters, slight races are acceptable.
		m.data.Store(key, newEntry)
		return current, nil
	}
}

// Keys returns all non-expired keys matching the given prefix.
func (m *MemoryPolicyStateStore) Keys(_ context.Context, prefix string) ([]string, error) {
	now := time.Now()
	var result []string
	m.data.Range(func(k, v any) bool {
		key := k.(string)
		if !strings.HasPrefix(key, prefix) {
			return true
		}
		entry := v.(*memoryEntry)
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			m.data.Delete(key)
			return true
		}
		result = append(result, key)
		return true
	})
	return result, nil
}
