package keys

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeKeyFile(t *testing.T, dir string, keys []fileKeyEntry) string {
	t.Helper()
	path := filepath.Join(dir, "keys.json")
	kf := fileKeyFile{Keys: keys}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func testKeys() []fileKeyEntry {
	return []fileKeyEntry{
		{
			VirtualKey: VirtualKey{
				ID:               "vk-test-1",
				Name:             "Test Key 1",
				WorkspaceID:      "ws-1",
				Status:           "active",
				AllowedModels:    []string{"gpt-4o", "gpt-4o-mini"},
				AllowedProviders: []string{"openai"},
				MaxTokensPerMin:  10000,
				MaxTokens:        1000000,
				ProviderKeys: map[string]string{
					"openai": "sk-real-openai-key",
				},
			},
			RawKey: "sk-sb-testkey1abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
		},
		{
			VirtualKey: VirtualKey{
				ID:            "vk-test-2",
				Name:          "Test Key 2",
				WorkspaceID:   "ws-1",
				Status:        "active",
				MaxTokens:     500000,
				DowngradeMap:  map[string]string{"gpt-4o": "gpt-4o-mini"},
				TokenBudgetAction: "downgrade",
			},
			RawKey: "sk-sb-testkey2abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
		},
		{
			VirtualKey: VirtualKey{
				ID:          "vk-revoked",
				Name:        "Revoked Key",
				WorkspaceID: "ws-1",
				Status:      "revoked",
			},
			RawKey: "sk-sb-revokedabcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
	}
}

func TestFileStore_Load(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, testKeys())

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	// Should have 3 keys loaded
	keys, err := fs.List(context.Background(), "ws-1", ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
}

func TestFileStore_GetByHash(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, testKeys())

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	hash := HashKey("sk-sb-testkey1abcdef1234567890abcdef1234567890abcdef1234567890abcdef12")
	vk, err := fs.GetByHash(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if vk.ID != "vk-test-1" {
		t.Fatalf("expected vk-test-1, got %s", vk.ID)
	}
	if vk.Name != "Test Key 1" {
		t.Fatalf("expected Test Key 1, got %s", vk.Name)
	}
}

func TestFileStore_GetByID(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, testKeys())

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	vk, err := fs.GetByID(context.Background(), "vk-test-2")
	if err != nil {
		t.Fatal(err)
	}
	if vk.MaxTokens != 500000 {
		t.Fatalf("expected MaxTokens 500000, got %d", vk.MaxTokens)
	}
	if vk.TokenBudgetAction != "downgrade" {
		t.Fatalf("expected downgrade action, got %s", vk.TokenBudgetAction)
	}
}

func TestFileStore_ProviderKeys(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, testKeys())

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	vk, err := fs.GetByID(context.Background(), "vk-test-1")
	if err != nil {
		t.Fatal(err)
	}
	if vk.ProviderKeys["openai"] != "sk-real-openai-key" {
		t.Fatalf("expected openai key, got %s", vk.ProviderKeys["openai"])
	}
}

func TestFileStore_ListFilterByStatus(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, testKeys())

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	active, err := fs.List(context.Background(), "ws-1", ListOpts{Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("expected 2 active keys, got %d", len(active))
	}

	revoked, err := fs.List(context.Background(), "ws-1", ListOpts{Status: "revoked"})
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 {
		t.Fatalf("expected 1 revoked key, got %d", len(revoked))
	}
}

func TestFileStore_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, testKeys())

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fs.GetByID(context.Background(), "nonexistent")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}

	_, err = fs.GetByHash(context.Background(), "nonexistent-hash")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestFileStore_ReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, testKeys())

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	if err := fs.Create(ctx, &VirtualKey{ID: "new"}); err != ErrReadOnly {
		t.Fatalf("Create should return ErrReadOnly, got %v", err)
	}
	if err := fs.Update(ctx, "vk-test-1", map[string]any{"name": "x"}); err != ErrReadOnly {
		t.Fatalf("Update should return ErrReadOnly, got %v", err)
	}
	if err := fs.Revoke(ctx, "vk-test-1"); err != ErrReadOnly {
		t.Fatalf("Revoke should return ErrReadOnly, got %v", err)
	}
	if err := fs.Delete(ctx, "vk-test-1"); err != ErrReadOnly {
		t.Fatalf("Delete should return ErrReadOnly, got %v", err)
	}
}

func TestFileStore_NonexistentFile(t *testing.T) {
	_, err := NewFileStore("/nonexistent/path/keys.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestFileStore_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := NewFileStore(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFileStore_HotReload(t *testing.T) {
	dir := t.TempDir()
	initialKeys := testKeys()[:1] // Only first key
	path := writeKeyFile(t, dir, initialKeys)

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	// Verify initial state
	keys, _ := fs.List(context.Background(), "ws-1", ListOpts{})
	if len(keys) != 1 {
		t.Fatalf("expected 1 key initially, got %d", len(keys))
	}

	// Wait a moment so file modification time differs
	time.Sleep(50 * time.Millisecond)

	// Write updated file with all keys
	writeKeyFile(t, dir, testKeys())

	// Manually reload (simulates what WatchFile would do)
	if err := fs.Reload(); err != nil {
		t.Fatal(err)
	}

	// Verify new state
	keys, _ = fs.List(context.Background(), "ws-1", ListOpts{})
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys after reload, got %d", len(keys))
	}
}

func TestFileStore_DefaultStatus(t *testing.T) {
	dir := t.TempDir()
	// Key with no status should default to "active"
	entry := fileKeyEntry{
		VirtualKey: VirtualKey{
			ID:          "vk-no-status",
			Name:        "No Status",
			WorkspaceID: "ws-1",
		},
		RawKey: "sk-sb-nostatusabcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}
	path := writeKeyFile(t, dir, []fileKeyEntry{entry})

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	vk, err := fs.GetByID(context.Background(), "vk-no-status")
	if err != nil {
		t.Fatal(err)
	}
	if vk.Status != "active" {
		t.Fatalf("expected default status 'active', got %s", vk.Status)
	}
}

func TestFileStore_CopyProtection(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, testKeys())

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	// Modifying returned key should not affect store
	vk, _ := fs.GetByID(context.Background(), "vk-test-1")
	vk.Name = "Modified"

	vk2, _ := fs.GetByID(context.Background(), "vk-test-1")
	if vk2.Name == "Modified" {
		t.Fatal("store should return copies, not references")
	}
}
