package cacher

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
)

func getMemcachedClient(t *testing.T) *memcache.Client {
	t.Helper()
	servers := os.Getenv("MEMCACHED_SERVERS")
	if servers == "" {
		servers = "localhost:11211"
	}
	client := memcache.New(servers)
	client.Timeout = 1 * time.Second
	// Try a ping to see if memcached is available
	err := client.Set(&memcache.Item{Key: "__ping__", Value: []byte("1"), Expiration: 1})
	if err != nil {
		t.Skipf("memcached not available at %s: %v", servers, err)
	}
	return client
}

func newTestMemcachedCacher(t *testing.T) *MemcachedCacher {
	t.Helper()
	client := getMemcachedClient(t)
	return &MemcachedCacher{
		client:      client,
		driver:      DriverMemcached,
		prefix:      "test",
		maxItemSize: defaultMaxItemSize,
	}
}

func TestMemcachedPutAndGet(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	err := mc.Put(ctx, "test-type", "key1", bytes.NewReader([]byte("hello world")))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	reader, err := mc.Get(ctx, "test-type", "key1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)
	if buf.String() != "hello world" {
		t.Errorf("expected 'hello world', got %q", buf.String())
	}
}

func TestMemcachedGetNotFound(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	_, err := mc.Get(ctx, "test-type", "nonexistent-key-12345")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemcachedDelete(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	err := mc.Put(ctx, "test-type", "del-key", bytes.NewReader([]byte("to delete")))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	err = mc.Delete(ctx, "test-type", "del-key")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = mc.Get(ctx, "test-type", "del-key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestMemcachedDeleteMissing(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	// Deleting a nonexistent key should not return an error
	err := mc.Delete(ctx, "test-type", "never-existed-key-xyz")
	if err != nil {
		t.Errorf("Delete of nonexistent key should return nil, got %v", err)
	}
}

func TestMemcachedPutWithExpires(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	err := mc.PutWithExpires(ctx, "test-type", "ttl-key", bytes.NewReader([]byte("expires soon")), 2*time.Second)
	if err != nil {
		t.Fatalf("PutWithExpires failed: %v", err)
	}

	// Should exist immediately
	reader, err := mc.Get(ctx, "test-type", "ttl-key")
	if err != nil {
		t.Fatalf("Get failed immediately after PutWithExpires: %v", err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)
	if buf.String() != "expires soon" {
		t.Errorf("expected 'expires soon', got %q", buf.String())
	}

	// Wait for TTL to expire
	time.Sleep(3 * time.Second)

	_, err = mc.Get(ctx, "test-type", "ttl-key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after TTL expiry, got %v", err)
	}
}

func TestMemcachedIncrement(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	// Clean up from any previous test run
	mc.Delete(ctx, "test-type", "counter-key")

	val, err := mc.Increment(ctx, "test-type", "counter-key", 5)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val != 5 {
		t.Errorf("expected 5, got %d", val)
	}

	val, err = mc.Increment(ctx, "test-type", "counter-key", 3)
	if err != nil {
		t.Fatalf("second Increment failed: %v", err)
	}
	if val != 8 {
		t.Errorf("expected 8, got %d", val)
	}
}

func TestMemcachedIncrementWithExpires(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	// Clean up from any previous test run
	mc.Delete(ctx, "test-type", "ttl-counter-key")

	val, err := mc.IncrementWithExpires(ctx, "test-type", "ttl-counter-key", 10, 2*time.Second)
	if err != nil {
		t.Fatalf("IncrementWithExpires failed: %v", err)
	}
	if val != 10 {
		t.Errorf("expected 10, got %d", val)
	}

	// Wait for TTL
	time.Sleep(3 * time.Second)

	_, err = mc.Get(ctx, "test-type", "ttl-counter-key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after TTL, got %v", err)
	}
}

func TestMemcachedLongKeyHashing(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	// Create a key longer than 250 bytes
	longKey := strings.Repeat("a", 300)

	err := mc.Put(ctx, "test-type", longKey, bytes.NewReader([]byte("long key value")))
	if err != nil {
		t.Fatalf("Put with long key failed: %v", err)
	}

	reader, err := mc.Get(ctx, "test-type", longKey)
	if err != nil {
		t.Fatalf("Get with long key failed: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)
	if buf.String() != "long key value" {
		t.Errorf("expected 'long key value', got %q", buf.String())
	}

	// Verify the formatted key is within limits
	formatted := mc.formatKey("test-type", longKey)
	if len(formatted) > maxMemcachedKeyLen {
		t.Errorf("formatted key exceeds %d bytes: len=%d", maxMemcachedKeyLen, len(formatted))
	}
}

func TestMemcachedMaxItemSize(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	mc.maxItemSize = 100 // Set a small limit for testing
	ctx := context.Background()

	// Try to store an item larger than the limit
	largeData := bytes.Repeat([]byte("x"), 200)
	err := mc.Put(ctx, "test-type", "large-key", bytes.NewReader(largeData))
	if err != nil {
		t.Errorf("Put of oversized item should return nil (skip), got error: %v", err)
	}

	// The item should not have been stored
	_, err = mc.Get(ctx, "test-type", "large-key")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for oversized item, got %v", err)
	}
}

func TestMemcachedDeleteByPatternNoOp(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	err := mc.DeleteByPattern(ctx, "test-type", "some-pattern*")
	if err != nil {
		t.Errorf("DeleteByPattern should be no-op returning nil, got %v", err)
	}
}

func TestMemcachedListKeysNoOp(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	ctx := context.Background()

	keys, err := mc.ListKeys(ctx, "test-type", "*")
	if err != nil {
		t.Errorf("ListKeys should return nil error, got %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListKeys should return empty slice, got %v", keys)
	}
}

func TestMemcachedDriver(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	if mc.Driver() != DriverMemcached {
		t.Errorf("expected driver %q, got %q", DriverMemcached, mc.Driver())
	}
}

func TestMemcachedClose(t *testing.T) {
	mc := newTestMemcachedCacher(t)
	err := mc.Close()
	if err != nil {
		t.Errorf("Close should return nil, got %v", err)
	}
}

func TestNewMemcachedCacherMissingServers(t *testing.T) {
	t.Parallel()
	_, err := NewMemcachedCacher(Settings{
		Driver: DriverMemcached,
		Params: map[string]string{},
	})
	if err != ErrInvalidConfiguration {
		t.Errorf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestNewMemcachedCacherInvalidParams(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		params map[string]string
	}{
		{
			name:   "invalid max_item_size",
			params: map[string]string{"servers": "localhost:11211", "max_item_size": "not-a-number"},
		},
		{
			name:   "invalid connect_timeout",
			params: map[string]string{"servers": "localhost:11211", "connect_timeout": "bad"},
		},
		{
			name:   "invalid timeout",
			params: map[string]string{"servers": "localhost:11211", "timeout": "bad"},
		},
		{
			name:   "invalid max_idle_conns",
			params: map[string]string{"servers": "localhost:11211", "max_idle_conns": "bad"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewMemcachedCacher(Settings{
				Driver: DriverMemcached,
				Params: tt.params,
			})
			if err == nil {
				t.Error("expected error for invalid params, got nil")
			}
		})
	}
}

func TestNewMemcachedCacherValidConfig(t *testing.T) {
	cacher, err := NewMemcachedCacher(Settings{
		Driver: DriverMemcached,
		Params: map[string]string{
			"servers":         "localhost:11211",
			"prefix":          "myprefix",
			"max_item_size":   "2097152",
			"connect_timeout": "200",
			"timeout":         "100",
			"max_idle_conns":  "20",
		},
	})
	if err != nil {
		t.Fatalf("NewMemcachedCacher failed: %v", err)
	}
	if cacher.Driver() != DriverMemcached {
		t.Errorf("expected driver %q, got %q", DriverMemcached, cacher.Driver())
	}
}
