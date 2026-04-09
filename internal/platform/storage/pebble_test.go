package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/redis/go-redis/v9"
)

func TestPebbleStorageGet(t *testing.T) {
	tmpDir := t.TempDir()
	ps := createTestPebbleStorage(t, tmpDir)
	defer ps.Close()

	ctx := context.Background()

	// Test Put and Get
	testData := []byte(`{"id":"123","hostname":"example.com"}`)
	if err := ps.Put(ctx, "example.com", testData); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	data, err := ps.Get(ctx, "example.com")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if !bytes.Equal(data, testData) {
		t.Errorf("Get returned wrong data: %v != %v", string(data), string(testData))
	}
}

func TestPebbleStorageDelete(t *testing.T) {
	tmpDir := t.TempDir()
	ps := createTestPebbleStorage(t, tmpDir)
	defer ps.Close()

	ctx := context.Background()

	// Put and then delete
	testData := []byte(`{"id":"123","hostname":"example.com"}`)
	if err := ps.Put(ctx, "example.com", testData); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	if err := ps.Delete(ctx, "example.com"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err := ps.Get(ctx, "example.com")
	if err != ErrKeyNotFound {
		t.Errorf("Get after delete should return ErrKeyNotFound, got: %v", err)
	}
}

func TestPebbleStorageListKeys(t *testing.T) {
	tmpDir := t.TempDir()
	ps := createTestPebbleStorage(t, tmpDir)
	defer ps.Close()

	ctx := context.Background()

	// Put multiple keys
	keys := []string{"example.com", "test.com", "sample.com"}
	for _, key := range keys {
		data := []byte(`{"id":"` + key + `","hostname":"` + key + `"}`)
		if err := ps.Put(ctx, key, data); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	// List keys
	listedKeys, err := ps.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(listedKeys) != len(keys) {
		t.Errorf("ListKeys returned %d keys, expected %d", len(listedKeys), len(keys))
	}
}

func TestPebbleStorageSyncFromBackend(t *testing.T) {
	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers are present
		if r.Header.Get("X-Timestamp") == "" {
			t.Error("X-Timestamp header missing")
		}
		if r.Header.Get("X-Signature") == "" {
			t.Error("X-Signature header missing")
		}

		// Return mock origin data
		response := OriginListResponse{
			Origins: []json.RawMessage{
				json.RawMessage(`{"id":"1","hostname":"example.com"}`),
				json.RawMessage(`{"id":"2","hostname":"test.com"}`),
			},
			Count:     2,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	ps := &PebbleStorage{
		dbPath:       tmpDir,
		remoteURL:    server.URL,
		sharedSecret: "test-secret",
		syncInterval: time.Minute,
		driver:       "pebble",
		done:         make(chan struct{}),
	}

	// Open PebbleDB
	db, err := pebble.Open(tmpDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Failed to open pebble: %v", err)
	}
	ps.db = db
	defer ps.Close()

	ctx := context.Background()
	if err := ps.syncFromBackend(ctx); err != nil {
		t.Fatalf("syncFromBackend failed: %v", err)
	}

	// Verify data was stored
	keys, err := ps.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}
}

func TestPebbleStorageSyncFromBackendIncludesClusterQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cluster_id"); got != "cluster-123" {
			t.Fatalf("expected cluster_id query parameter, got %q", got)
		}

		response := OriginListResponse{
			Origins:   []json.RawMessage{},
			Count:     0,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	ps := &PebbleStorage{
		dbPath:       tmpDir,
		remoteURL:    server.URL,
		clusterID:    "cluster-123",
		sharedSecret: "test-secret",
		syncInterval: time.Minute,
		driver:       "pebble",
		done:         make(chan struct{}),
	}

	db, err := pebble.Open(tmpDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Failed to open pebble: %v", err)
	}
	ps.db = db
	defer ps.Close()

	if err := ps.syncFromBackend(context.Background()); err != nil {
		t.Fatalf("syncFromBackend failed: %v", err)
	}
}

func TestPebbleStorageDeleteByPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	ps := createTestPebbleStorage(t, tmpDir)
	defer ps.Close()

	ctx := context.Background()

	// Put keys with common prefix
	keys := []string{"app-1.com", "app-2.com", "web-1.com"}
	for _, key := range keys {
		data := []byte(`{"id":"` + key + `","hostname":"` + key + `"}`)
		if err := ps.Put(ctx, key, data); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	// Delete by prefix
	if err := ps.DeleteByPrefix(ctx, "app-"); err != nil {
		t.Fatalf("DeleteByPrefix failed: %v", err)
	}

	// Verify app-1 and app-2 are deleted
	_, err := ps.Get(ctx, "app-1.com")
	if err != ErrKeyNotFound {
		t.Error("app-1.com should be deleted")
	}

	_, err = ps.Get(ctx, "app-2.com")
	if err != ErrKeyNotFound {
		t.Error("app-2.com should be deleted")
	}

	// Verify web-1 still exists
	data, err := ps.Get(ctx, "web-1.com")
	if err != nil {
		t.Errorf("web-1.com should still exist, got error: %v", err)
	}
	if len(data) == 0 {
		t.Error("web-1.com data is empty")
	}
}

func TestPebbleStorageContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	ps := createTestPebbleStorage(t, tmpDir)
	defer ps.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// All operations should return context error
	if err := ps.Put(ctx, "test", []byte("data")); err == nil {
		t.Error("Put should fail with cancelled context")
	}

	if _, err := ps.Get(ctx, "test"); err == nil {
		t.Error("Get should fail with cancelled context")
	}

	if _, err := ps.ListKeys(ctx); err == nil {
		t.Error("ListKeys should fail with cancelled context")
	}
}

func TestPebbleStorageValidateProxyAPIKey(t *testing.T) {
	// Create mock HTTP server for validation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"key_id":   "key-123",
			"key_name": "production",
		})
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	ps := &PebbleStorage{
		dbPath:       tmpDir,
		remoteURL:    server.URL,
		sharedSecret: "test-secret",
		driver:       "pebble",
		done:         make(chan struct{}),
	}

	db, err := pebble.Open(tmpDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Failed to open pebble: %v", err)
	}
	ps.db = db
	defer ps.Close()

	ctx := context.Background()
	result, err := ps.ValidateProxyAPIKey(ctx, "origin-123", "valid-key")
	if err != nil {
		t.Fatalf("ValidateProxyAPIKey failed: %v", err)
	}

	if result.ProxyKeyID != "key-123" {
		t.Errorf("Expected key_id 'key-123', got '%s'", result.ProxyKeyID)
	}

	if result.ProxyKeyName != "production" {
		t.Errorf("Expected key_name 'production', got '%s'", result.ProxyKeyName)
	}
}

func TestPebbleStorageStartStrictSync(t *testing.T) {
	tmpDir := t.TempDir()
	ps := &PebbleStorage{
		dbPath:            tmpDir,
		remoteURL:         "http://127.0.0.1:1",
		sharedSecret:      "test-secret",
		syncInterval:      time.Minute,
		driver:            "pebble",
		done:              make(chan struct{}),
		syncClient:        &http.Client{Timeout: 100 * time.Millisecond},
		strictStartupSync: true,
	}
	defer ps.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := ps.Start(ctx); err == nil {
		t.Fatalf("expected strict startup sync to fail when backend is unavailable")
	}
}

func TestPebbleStorageHandleRedisStreamMessageInvalidHostname(t *testing.T) {
	tmpDir := t.TempDir()
	ps := createTestPebbleStorage(t, tmpDir)
	defer ps.Close()

	ctx := context.Background()
	msg := redis.XMessage{
		ID:     "1-0",
		Values: map[string]any{"hostname": 123},
	}

	// Should not panic
	ps.handleRedisStreamMessage(ctx, "origins:deleted", msg)
}

// Helper function to create a test PebbleStorage with mock HTTP backend
func createTestPebbleStorage(t *testing.T, tmpDir string) *PebbleStorage {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := OriginListResponse{
			Origins:   []json.RawMessage{},
			Count:     0,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)

	ps := &PebbleStorage{
		dbPath:       tmpDir,
		remoteURL:    server.URL,
		sharedSecret: "test-secret",
		syncInterval: time.Minute,
		driver:       "pebble",
		done:         make(chan struct{}),
	}

	db, err := pebble.Open(tmpDir, &pebble.Options{})
	if err != nil {
		t.Fatalf("Failed to open pebble: %v", err)
	}
	ps.db = db

	return ps
}
