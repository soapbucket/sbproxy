// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// DistributedLock provides distributed mutual exclusion for coordinating
// work across multiple proxy instances (e.g. cache revalidation).
type DistributedLock interface {
	// TryAcquire attempts to acquire a lock for the given key with the specified TTL.
	// Returns true if the lock was acquired, false if it is already held.
	TryAcquire(ctx context.Context, key string, ttl time.Duration) (bool, error)

	// Release releases a previously acquired lock. Only the instance that
	// acquired the lock can release it (owner check).
	Release(ctx context.Context, key string) error
}

// NoopDistributedLock is a no-op implementation for single-instance mode.
// TryAcquire always succeeds and Release is a no-op.
type NoopDistributedLock struct{}

// TryAcquire always returns true (lock acquired) for single-instance mode.
func (n *NoopDistributedLock) TryAcquire(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return true, nil
}

// Release is a no-op for single-instance mode.
func (n *NoopDistributedLock) Release(_ context.Context, _ string) error {
	return nil
}

// RedisDistributedLock implements DistributedLock using Redis SET NX PX.
// The lock value is a unique instance ID (hostname:pid) so that only the
// owner can release it via a Lua script.
type RedisDistributedLock struct {
	client    *redis.Client
	keyPrefix string
	instanceID string
}

// releaseScript is a Lua script that only deletes the key if the value matches.
// This prevents one instance from releasing another instance's lock.
const releaseScript = `
if redis.call("get", KEYS[1]) == ARGV[1] then
	return redis.call("del", KEYS[1])
else
	return 0
end
`

// NewRedisDistributedLock creates a new Redis-backed distributed lock.
// The keyPrefix is prepended to all lock keys (e.g. "lock:refresh").
func NewRedisDistributedLock(client *redis.Client, keyPrefix string) *RedisDistributedLock {
	hostname, _ := os.Hostname()
	instanceID := fmt.Sprintf("%s:%d", hostname, os.Getpid())

	return &RedisDistributedLock{
		client:     client,
		keyPrefix:  keyPrefix,
		instanceID: instanceID,
	}
}

func (r *RedisDistributedLock) fullKey(key string) string {
	return r.keyPrefix + ":" + key
}

// TryAcquire attempts to acquire a lock using SET key value NX PX ttl.
// Returns true if the lock was acquired, false if already held by another instance.
func (r *RedisDistributedLock) TryAcquire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	ok, err := r.client.SetNX(ctx, r.fullKey(key), r.instanceID, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis lock acquire %s: %w", r.fullKey(key), err)
	}
	return ok, nil
}

// Release releases the lock only if the current instance owns it.
// Uses a Lua script to atomically check-and-delete.
func (r *RedisDistributedLock) Release(ctx context.Context, key string) error {
	result, err := r.client.Eval(ctx, releaseScript, []string{r.fullKey(key)}, r.instanceID).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("redis lock release %s: %w", r.fullKey(key), err)
	}
	// result == 0 means the lock was not ours (or already expired), which is fine
	_ = result
	return nil
}
