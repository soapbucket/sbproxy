package ai

import (
	"context"
	"sync"
	"testing"

	json "github.com/goccy/go-json"
)

func TestConfigVersion_Create(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	data := json.RawMessage(`{"model":"gpt-4o","temperature":0.7}`)
	v, err := mgr.CreateVersion(ctx, "config-1", data, "admin", "initial config")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Version != 1 {
		t.Errorf("expected version 1, got %d", v.Version)
	}
	if v.ConfigID != "config-1" {
		t.Errorf("expected config-1, got %q", v.ConfigID)
	}
	if v.CreatedBy != "admin" {
		t.Errorf("expected admin, got %q", v.CreatedBy)
	}
	if v.Comment != "initial config" {
		t.Errorf("expected initial config, got %q", v.Comment)
	}
	if !v.Active {
		t.Error("expected version to be active")
	}
	if v.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestConfigVersion_AutoIncrement(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	v1, err := mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":1}`), "admin", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v1.Version != 1 {
		t.Errorf("expected version 1, got %d", v1.Version)
	}

	v2, err := mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":2}`), "admin", "v2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v2.Version != 2 {
		t.Errorf("expected version 2, got %d", v2.Version)
	}

	v3, err := mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":3}`), "admin", "v3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v3.Version != 3 {
		t.Errorf("expected version 3, got %d", v3.Version)
	}
}

func TestConfigVersion_GetActive(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":1}`), "admin", "v1")
	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":2}`), "admin", "v2")

	active, err := mgr.GetActive(ctx, "config-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active.Version != 2 {
		t.Errorf("expected active version 2, got %d", active.Version)
	}
}

func TestConfigVersion_Rollback(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":1}`), "admin", "v1")
	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":2}`), "admin", "v2")
	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":3}`), "admin", "v3")

	// Active should be v3.
	active, _ := mgr.GetActive(ctx, "config-1")
	if active.Version != 3 {
		t.Fatalf("expected active version 3, got %d", active.Version)
	}

	// Rollback to v1.
	rolled, err := mgr.Rollback(ctx, "config-1", 1)
	if err != nil {
		t.Fatalf("rollback error: %v", err)
	}
	if rolled.Version != 1 {
		t.Errorf("expected rolled back version 1, got %d", rolled.Version)
	}
	if !rolled.Active {
		t.Error("expected rolled back version to be active")
	}

	// Verify active is now v1.
	active, _ = mgr.GetActive(ctx, "config-1")
	if active.Version != 1 {
		t.Errorf("expected active version 1 after rollback, got %d", active.Version)
	}
}

func TestConfigVersion_History(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{}`), "admin", "")
	}

	// Get all history.
	history, err := mgr.History(ctx, "config-1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(history) != 5 {
		t.Errorf("expected 5 versions, got %d", len(history))
	}

	// Get limited history.
	history, err = mgr.History(ctx, "config-1", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(history) != 3 {
		t.Errorf("expected 3 versions with limit, got %d", len(history))
	}

	// Most recent should be first (desc order).
	if history[0].Version != 5 {
		t.Errorf("expected most recent version (5) first, got %d", history[0].Version)
	}
}

func TestConfigVersion_Diff(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"model":"gpt-4o","temperature":0.7}`), "admin", "v1")
	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"model":"gpt-4o-mini","temperature":0.7,"max_tokens":1000}`), "admin", "v2")

	diff, err := mgr.Diff(ctx, "config-1", 1, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// model changed.
	if _, ok := diff["model"]; !ok {
		t.Error("expected model in diff")
	}

	// max_tokens added.
	if _, ok := diff["max_tokens"]; !ok {
		t.Error("expected max_tokens in diff (new field)")
	}

	// temperature unchanged - should NOT be in diff.
	if _, ok := diff["temperature"]; ok {
		t.Error("temperature should not be in diff (unchanged)")
	}
}

func TestConfigVersion_PinToKey(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":1}`), "admin", "v1")
	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":2}`), "admin", "v2")

	// Pin key to v1.
	err := mgr.PinToKey(ctx, "config-1", 1, "api-key-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify pinned version.
	pinnedVersion, found := store.GetPinnedVersion("config-1", "api-key-123")
	if !found {
		t.Fatal("expected pinned version to be found")
	}
	if pinnedVersion != 1 {
		t.Errorf("expected pinned version 1, got %d", pinnedVersion)
	}

	// Pin to nonexistent version should fail.
	err = mgr.PinToKey(ctx, "config-1", 99, "api-key-123")
	if err == nil {
		t.Error("expected error pinning to nonexistent version")
	}
}

func TestConfigVersion_ListVersions(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":1}`), "admin", "first")
	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":2}`), "admin", "second")

	versions, err := store.ListVersions(ctx, "config-1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions))
	}

	// Different config should be isolated.
	versions, err = store.ListVersions(ctx, "config-2", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("expected 0 versions for config-2, got %d", len(versions))
	}
}

func TestConfigVersion_NotFound(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	_, err := mgr.GetActive(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent config")
	}

	_, err = mgr.Rollback(ctx, "nonexistent", 1)
	if err == nil {
		t.Error("expected error for rollback on nonexistent config")
	}

	_, err = mgr.Diff(ctx, "nonexistent", 1, 2)
	if err == nil {
		t.Error("expected error for diff on nonexistent config")
	}
}

func TestConfigVersion_ConcurrentAccess(t *testing.T) {
	store := NewMemoryConfigVersionStore()
	mgr := NewConfigVersionManager(store)
	ctx := context.Background()

	// Pre-create a config.
	mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{"v":0}`), "admin", "init")

	var wg sync.WaitGroup

	// Concurrent version creation.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := mgr.CreateVersion(ctx, "config-1", json.RawMessage(`{}`), "admin", "concurrent")
			if err != nil {
				t.Errorf("concurrent create error: %v", err)
			}
		}()
	}

	// Concurrent reads.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.GetActive(ctx, "config-1")
			_, _ = mgr.History(ctx, "config-1", 5)
		}()
	}

	wg.Wait()
}
