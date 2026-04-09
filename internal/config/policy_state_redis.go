// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisPolicyStateStore implements PolicyStateStore using Redis.
// Keys are workspace-namespaced: "policy:{workspace}:{type}:{key}".
type RedisPolicyStateStore struct {
	client    *redis.Client
	keyPrefix string // e.g. "policy:{workspaceID}:{policyType}"
}

// NewRedisPolicyStateStore creates a new Redis-backed policy state store.
// The keyPrefix is prepended to all keys and should include workspace and policy
// type information (e.g. "policy:ws123:ddos").
func NewRedisPolicyStateStore(client *redis.Client, keyPrefix string) *RedisPolicyStateStore {
	return &RedisPolicyStateStore{
		client:    client,
		keyPrefix: keyPrefix,
	}
}

func (r *RedisPolicyStateStore) fullKey(key string) string {
	return r.keyPrefix + ":" + key
}

// Get retrieves a value by key. Returns nil, nil if the key does not exist.
func (r *RedisPolicyStateStore) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := r.client.Get(ctx, r.fullKey(key)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis get %s: %w", r.fullKey(key), err)
	}
	return val, nil
}

// Set stores a value with an optional TTL. A zero TTL means no expiration.
func (r *RedisPolicyStateStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	fk := r.fullKey(key)
	if ttl > 0 {
		if err := r.client.Set(ctx, fk, value, ttl).Err(); err != nil {
			return fmt.Errorf("redis set %s: %w", fk, err)
		}
		return nil
	}
	if err := r.client.Set(ctx, fk, value, 0).Err(); err != nil {
		return fmt.Errorf("redis set %s: %w", fk, err)
	}
	return nil
}

// Delete removes a key.
func (r *RedisPolicyStateStore) Delete(ctx context.Context, key string) error {
	if err := r.client.Del(ctx, r.fullKey(key)).Err(); err != nil {
		return fmt.Errorf("redis del %s: %w", r.fullKey(key), err)
	}
	return nil
}

// Increment atomically increments a counter and sets the TTL on first creation.
// Returns the new counter value.
func (r *RedisPolicyStateStore) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	fk := r.fullKey(key)
	val, err := r.client.Incr(ctx, fk).Result()
	if err != nil {
		return 0, fmt.Errorf("redis incr %s: %w", fk, err)
	}
	// Set TTL only when the counter was just created (value == 1)
	if val == 1 && ttl > 0 {
		if err := r.client.Expire(ctx, fk, ttl).Err(); err != nil {
			return val, fmt.Errorf("redis expire %s: %w", fk, err)
		}
	}
	return val, nil
}

// Keys returns all keys matching the given prefix using SCAN for safety.
func (r *RedisPolicyStateStore) Keys(ctx context.Context, prefix string) ([]string, error) {
	pattern := r.fullKey(prefix) + "*"
	var allKeys []string
	var cursor uint64

	for {
		keys, nextCursor, err := r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("redis scan %s: %w", pattern, err)
		}
		allKeys = append(allKeys, keys...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return allKeys, nil
}
