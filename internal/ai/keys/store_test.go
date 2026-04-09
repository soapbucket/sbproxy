package keys

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore_CreateAndGetByID(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	vk := &VirtualKey{
		ID:          "vk-test-001",
		Name:        "test key",
		HashedKey:   "abc123hash",
		WorkspaceID: "ws-1",
		Status:      "active",
		CreatedAt:   time.Now().UTC(),
	}

	if err := store.Create(ctx, vk); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := store.GetByID(ctx, "vk-test-001")
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.Name != "test key" {
		t.Errorf("GetByID() name = %q, want %q", got.Name, "test key")
	}
	if got.WorkspaceID != "ws-1" {
		t.Errorf("GetByID() workspace_id = %q, want %q", got.WorkspaceID, "ws-1")
	}
}

func TestMemoryStore_CreateDuplicate(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	vk := &VirtualKey{
		ID:          "vk-test-001",
		HashedKey:   "abc123hash",
		WorkspaceID: "ws-1",
		Status:      "active",
	}

	if err := store.Create(ctx, vk); err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	if err := store.Create(ctx, vk); err == nil {
		t.Fatal("second Create() expected error for duplicate ID")
	}
}

func TestMemoryStore_GetByHash(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	vk := &VirtualKey{
		ID:          "vk-test-001",
		Name:        "hash-lookup key",
		HashedKey:   "hash-abc-123",
		WorkspaceID: "ws-1",
		Status:      "active",
	}

	if err := store.Create(ctx, vk); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := store.GetByHash(ctx, "hash-abc-123")
	if err != nil {
		t.Fatalf("GetByHash() error = %v", err)
	}
	if got.ID != "vk-test-001" {
		t.Errorf("GetByHash() id = %q, want %q", got.ID, "vk-test-001")
	}
}

func TestMemoryStore_GetByHash_NotFound(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	_, err := store.GetByHash(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("GetByHash() error = %v, want ErrKeyNotFound", err)
	}
}

func TestMemoryStore_List(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	for i, ws := range []string{"ws-1", "ws-1", "ws-2"} {
		vk := &VirtualKey{
			ID:          "vk-test-" + string(rune('a'+i)),
			HashedKey:   "hash-" + string(rune('a'+i)),
			WorkspaceID: ws,
			Status:      "active",
		}
		if err := store.Create(ctx, vk); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	keys, err := store.List(ctx, "ws-1", ListOpts{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("List(ws-1) got %d keys, want 2", len(keys))
	}

	keys, err = store.List(ctx, "ws-2", ListOpts{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("List(ws-2) got %d keys, want 1", len(keys))
	}
}

func TestMemoryStore_ListWithStatusFilter(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Create(ctx, &VirtualKey{ID: "vk-1", HashedKey: "h1", WorkspaceID: "ws-1", Status: "active"})
	store.Create(ctx, &VirtualKey{ID: "vk-2", HashedKey: "h2", WorkspaceID: "ws-1", Status: "revoked"})

	keys, _ := store.List(ctx, "ws-1", ListOpts{Status: "active"})
	if len(keys) != 1 {
		t.Errorf("List(status=active) got %d keys, want 1", len(keys))
	}
	if keys[0].ID != "vk-1" {
		t.Errorf("List(status=active) got id=%q, want vk-1", keys[0].ID)
	}
}

func TestMemoryStore_Update(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Create(ctx, &VirtualKey{
		ID:          "vk-1",
		HashedKey:   "h1",
		WorkspaceID: "ws-1",
		Name:        "original",
		Status:      "active",
	})

	err := store.Update(ctx, "vk-1", map[string]any{
		"name": "updated",
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	got, _ := store.GetByID(ctx, "vk-1")
	if got.Name != "updated" {
		t.Errorf("after Update() name = %q, want %q", got.Name, "updated")
	}
}

func TestMemoryStore_Update_NotFound(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	err := store.Update(ctx, "nonexistent", map[string]any{"name": "x"})
	if err != ErrKeyNotFound {
		t.Errorf("Update() error = %v, want ErrKeyNotFound", err)
	}
}

func TestMemoryStore_Revoke(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Create(ctx, &VirtualKey{
		ID:        "vk-1",
		HashedKey: "h1",
		WorkspaceID: "ws-1",
		Status:    "active",
	})

	if err := store.Revoke(ctx, "vk-1"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	got, _ := store.GetByID(ctx, "vk-1")
	if got.Status != "revoked" {
		t.Errorf("after Revoke() status = %q, want %q", got.Status, "revoked")
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Create(ctx, &VirtualKey{
		ID:        "vk-1",
		HashedKey: "h1",
		WorkspaceID: "ws-1",
		Status:    "active",
	})

	if err := store.Delete(ctx, "vk-1"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err := store.GetByID(ctx, "vk-1")
	if err != ErrKeyNotFound {
		t.Errorf("after Delete() GetByID error = %v, want ErrKeyNotFound", err)
	}

	_, err = store.GetByHash(ctx, "h1")
	if err != ErrKeyNotFound {
		t.Errorf("after Delete() GetByHash error = %v, want ErrKeyNotFound", err)
	}
}

func TestMemoryStore_ReturnsCopies(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	store.Create(ctx, &VirtualKey{
		ID:        "vk-1",
		HashedKey: "h1",
		WorkspaceID: "ws-1",
		Name:      "original",
		Status:    "active",
	})

	got1, _ := store.GetByID(ctx, "vk-1")
	got1.Name = "mutated"

	got2, _ := store.GetByID(ctx, "vk-1")
	if got2.Name != "original" {
		t.Error("store returned a reference instead of a copy - mutation leaked")
	}
}
