package storage

import (
	"context"
	"testing"
)

func TestLocalStorage_PutAndGet(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	key := "test.example.com"
	data := []byte(`{"id":"test-1","name":"Test"}`)

	if err := storage.Put(context.Background(), key, data); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, err := storage.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(got) != string(data) {
		t.Errorf("data mismatch: got %q, want %q", got, data)
	}

	// Verify data was copied, not aliased
	if len(data) > 0 && &data[0] == &got[0] {
		t.Error("data was aliased instead of copied")
	}
}

func TestLocalStorage_GetNotFound(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	_, err = storage.Get(context.Background(), "nonexistent.example.com")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestLocalStorage_GetByID(t *testing.T) {
	defer SetLocalOrigins(nil)

	// Seed with an origin that has an ID
	origins := map[string][]byte{
		"test.example.com": []byte(`{"id":"origin-123","name":"Test"}`),
	}
	SetLocalOrigins(origins)

	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	got, err := storage.GetByID(context.Background(), "origin-123")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}

	if string(got) != string(origins["test.example.com"]) {
		t.Errorf("data mismatch: got %q, want %q", got, origins["test.example.com"])
	}
}

func TestLocalStorage_ListKeys(t *testing.T) {
	defer SetLocalOrigins(nil)

	origins := map[string][]byte{
		"a.example.com": []byte(`{"id":"a"}`),
		"z.example.com": []byte(`{"id":"z"}`),
		"m.example.com": []byte(`{"id":"m"}`),
	}
	SetLocalOrigins(origins)

	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	keys, err := storage.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}

	// Verify sorted order
	expected := []string{"a.example.com", "m.example.com", "z.example.com"}
	for i, k := range keys {
		if k != expected[i] {
			t.Errorf("key[%d] = %q, want %q", i, k, expected[i])
		}
	}
}

func TestLocalStorage_Delete(t *testing.T) {
	defer SetLocalOrigins(nil)

	origins := map[string][]byte{
		"test.example.com": []byte(`{"id":"test-1","name":"Test"}`),
	}
	SetLocalOrigins(origins)

	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	if err := storage.Delete(context.Background(), "test.example.com"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = storage.Get(context.Background(), "test.example.com")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound after delete, got %v", err)
	}

	// Verify ID index was also cleaned up
	_, err = storage.GetByID(context.Background(), "test-1")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound for ID after delete, got %v", err)
	}
}

func TestLocalStorage_DeleteByPrefix(t *testing.T) {
	defer SetLocalOrigins(nil)

	origins := map[string][]byte{
		"api.example.com":    []byte(`{"id":"api"}`),
		"api-v2.example.com": []byte(`{"id":"api-v2"}`),
		"web.example.com":    []byte(`{"id":"web"}`),
	}
	SetLocalOrigins(origins)

	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	if err := storage.DeleteByPrefix(context.Background(), "api"); err != nil {
		t.Fatalf("DeleteByPrefix failed: %v", err)
	}

	keys, err := storage.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 1 || keys[0] != "web.example.com" {
		t.Errorf("expected only web.example.com, got %v", keys)
	}
}

func TestLocalStorage_DriverName(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	if storage.Driver() != DriverLocal {
		t.Errorf("Driver() = %q, want %q", storage.Driver(), DriverLocal)
	}
}

func TestLocalStorage_Close(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	if err := storage.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestLocalStorage_SetLocalOrigins(t *testing.T) {
	defer SetLocalOrigins(nil)

	// Set origins
	origins := map[string][]byte{
		"test.example.com": []byte(`{"id":"test"}`),
	}
	SetLocalOrigins(origins)

	// Create storage and verify it was seeded
	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	keys, err := storage.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}

	// Reset origins
	SetLocalOrigins(nil)

	// Create new storage and verify it's empty
	storage2, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	keys2, err := storage2.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys2) != 0 {
		t.Errorf("expected 0 keys after reset, got %d", len(keys2))
	}
}

func TestLocalStorage_ContextCancellation(t *testing.T) {
	defer SetLocalOrigins(nil)

	origins := map[string][]byte{
		"test.example.com": []byte(`{"id":"test"}`),
	}
	SetLocalOrigins(origins)

	storage, err := NewLocalStorage(Settings{})
	if err != nil {
		t.Fatalf("NewLocalStorage failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := storage.Get(ctx, "test.example.com"); err == nil {
		t.Error("expected error on cancelled context for Get")
	}

	if _, err := storage.GetByID(ctx, "test"); err == nil {
		t.Error("expected error on cancelled context for GetByID")
	}

	if _, err := storage.ListKeys(ctx); err == nil {
		t.Error("expected error on cancelled context for ListKeys")
	}

	if err := storage.Put(ctx, "key", []byte("data")); err == nil {
		t.Error("expected error on cancelled context for Put")
	}

	if err := storage.Delete(ctx, "key"); err == nil {
		t.Error("expected error on cancelled context for Delete")
	}

	if err := storage.DeleteByPrefix(ctx, "prefix"); err == nil {
		t.Error("expected error on cancelled context for DeleteByPrefix")
	}
}

func BenchmarkLocalStorageGet(b *testing.B) {
	defer SetLocalOrigins(nil)

	origins := make(map[string][]byte)
	for i := 0; i < 1000; i++ {
		origins[string(rune(i))] = []byte(`{"id":"test"}`)
	}
	SetLocalOrigins(origins)

	storage, _ := NewLocalStorage(Settings{})
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		storage.Get(ctx, "test")
	}
}
