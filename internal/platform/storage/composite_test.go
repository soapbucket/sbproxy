package storage

import (
	"context"
	"testing"
)

// mockStorage is a simple test storage implementation
type mockStorage struct {
	data        map[string][]byte
	readOnly    bool
	listKeysErr bool
}

func (m *mockStorage) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, ok := m.data[key]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return data, nil
}

func (m *mockStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrKeyNotFound
}

func (m *mockStorage) ListKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.listKeysErr {
		return nil, ErrListKeysNotSupported
	}
	var keys []string
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	return nil, nil
}

func (m *mockStorage) Put(ctx context.Context, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.readOnly {
		return ErrReadOnly
	}
	m.data[key] = data
	return nil
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.readOnly {
		return ErrReadOnly
	}
	delete(m.data, key)
	return nil
}

func (m *mockStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.readOnly {
		return ErrReadOnly
	}
	return nil
}

func (m *mockStorage) Driver() string { return "mock" }
func (m *mockStorage) Close() error   { return nil }

func (m *mockStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	return nil, ErrKeyNotFound
}

func TestCompositeStorage_GetFromPrimary(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(map[string][]byte{
		"test.example.com": []byte(`{"id":"test"}`),
	})

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{data: make(map[string][]byte)}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	data, err := cs.Get(context.Background(), "test.example.com")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(data) != `{"id":"test"}` {
		t.Errorf("data mismatch: got %q", data)
	}
}

func TestCompositeStorage_GetFallsBackToSecondary(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{
		data: map[string][]byte{
			"test.example.com": []byte(`{"id":"secondary"}`),
		},
	}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	data, err := cs.Get(context.Background(), "test.example.com")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(data) != `{"id":"secondary"}` {
		t.Errorf("data mismatch: got %q", data)
	}
}

func TestCompositeStorage_GetBothMiss(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{data: make(map[string][]byte)}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	_, err := cs.Get(context.Background(), "nonexistent.example.com")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestCompositeStorage_ListKeysUnion(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(map[string][]byte{
		"a.example.com": []byte(`{"id":"a"}`),
		"b.example.com": []byte(`{"id":"b"}`),
	})

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{
		data: map[string][]byte{
			"b.example.com": []byte(`{"id":"b-secondary"}`),
			"c.example.com": []byte(`{"id":"c"}`),
		},
	}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	keys, err := cs.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d: %v", len(keys), keys)
	}

	// Should have a, b, c (deduplicated)
	expected := map[string]bool{
		"a.example.com": true,
		"b.example.com": true,
		"c.example.com": true,
	}
	for _, k := range keys {
		if !expected[k] {
			t.Errorf("unexpected key: %q", k)
		}
	}
}

func TestCompositeStorage_PutWritesToBoth(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{data: make(map[string][]byte)}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	key := "test.example.com"
	data := []byte(`{"id":"test"}`)

	if err := cs.Put(context.Background(), key, data); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify in primary
	got, err := primary.Get(context.Background(), key)
	if err != nil || string(got) != string(data) {
		t.Errorf("data not in primary: %v", err)
	}

	// Verify in secondary
	if _, ok := secondary.data[key]; !ok {
		t.Error("data not in secondary")
	}
}

func TestCompositeStorage_SecondaryReadOnly(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{
		data:     make(map[string][]byte),
		readOnly: true,
	}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	key := "test.example.com"
	data := []byte(`{"id":"test"}`)

	// Put should succeed if only secondary is read-only
	if err := cs.Put(context.Background(), key, data); err != nil {
		t.Fatalf("Put failed even with read-only secondary: %v", err)
	}

	// Verify in primary
	got, err := primary.Get(context.Background(), key)
	if err != nil || string(got) != string(data) {
		t.Errorf("data not in primary: %v", err)
	}
}

func TestCompositeStorage_DriverName(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{data: make(map[string][]byte)}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	if cs.Driver() != DriverComposite {
		t.Errorf("Driver() = %q, want %q", cs.Driver(), DriverComposite)
	}
}

func TestCompositeStorage_Close(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(nil)

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{data: make(map[string][]byte)}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	if err := cs.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestCompositeStorage_GetByID(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(map[string][]byte{
		"test.example.com": []byte(`{"id":"test-1"}`),
	})

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{data: make(map[string][]byte)}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	data, err := cs.GetByID(context.Background(), "test-1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}

	if string(data) != `{"id":"test-1"}` {
		t.Errorf("data mismatch: got %q", data)
	}
}

func TestCompositeStorage_ListKeysSecondaryUnsupported(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(map[string][]byte{
		"a.example.com": []byte(`{"id":"a"}`),
	})

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{
		data:        make(map[string][]byte),
		listKeysErr: true,
	}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	keys, err := cs.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys failed even with unsupported secondary: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
}

func TestCompositeStorage_DeleteBothRemoved(t *testing.T) {
	defer SetLocalOrigins(nil)
	SetLocalOrigins(map[string][]byte{
		"test.example.com": []byte(`{"id":"test"}`),
	})

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{
		data: map[string][]byte{
			"test.example.com": []byte(`{"id":"test"}`),
		},
	}

	cs := &CompositeStorage{primary: primary, secondary: secondary}

	if err := cs.Delete(context.Background(), "test.example.com"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify removed from primary
	if _, err := primary.Get(context.Background(), "test.example.com"); err != ErrKeyNotFound {
		t.Error("key not removed from primary")
	}

	// Verify removed from secondary
	if _, ok := secondary.data["test.example.com"]; ok {
		t.Error("key not removed from secondary")
	}
}

func BenchmarkCompositeStorageGet(b *testing.B) {
	defer SetLocalOrigins(nil)

	origins := map[string][]byte{
		"test.example.com": []byte(`{"id":"test"}`),
	}
	SetLocalOrigins(origins)

	primary, _ := NewLocalStorage(Settings{})
	secondary := &mockStorage{data: make(map[string][]byte)}
	cs := &CompositeStorage{primary: primary, secondary: secondary}

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cs.Get(ctx, "test.example.com")
	}
}
