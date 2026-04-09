package prompts

import (
	"context"
	"testing"
)

func TestMemoryStore_CreateAndGet(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	p := &Prompt{
		ID:   "test-1",
		Name: "Test Prompt",
		Versions: []LegacyVersion{
			{Version: 1, Template: "Hello {{name}}"},
		},
	}
	if err := s.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, "test-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "test-1" {
		t.Errorf("ID = %q, want %q", got.ID, "test-1")
	}
	if got.Name != "Test Prompt" {
		t.Errorf("Name = %q, want %q", got.Name, "Test Prompt")
	}
	if got.ActiveVersion != 1 {
		t.Errorf("ActiveVersion = %d, want 1", got.ActiveVersion)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
	if len(got.Versions) != 1 {
		t.Fatalf("Versions length = %d, want 1", len(got.Versions))
	}
	if got.Versions[0].Template != "Hello {{name}}" {
		t.Errorf("Template = %q, want %q", got.Versions[0].Template, "Hello {{name}}")
	}
}

func TestMemoryStore_CreateDuplicate(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	p := &Prompt{ID: "dup", Name: "Dup"}
	if err := s.Create(ctx, p); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := s.Create(ctx, &Prompt{ID: "dup", Name: "Dup2"}); err == nil {
		t.Fatal("expected error for duplicate, got nil")
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Get(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestMemoryStore_List(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{ID: "a", Name: "A"})
	s.Create(ctx, &Prompt{ID: "b", Name: "B"})

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("List length = %d, want 2", len(list))
	}
}

func TestMemoryStore_GetVersion(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{
		ID:   "v",
		Name: "Versioned",
		Versions: []LegacyVersion{
			{Version: 1, Template: "v1"},
			{Version: 2, Template: "v2"},
		},
	})

	v, err := s.GetVersion(ctx, "v", 2)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if v.Template != "v2" {
		t.Errorf("Template = %q, want %q", v.Template, "v2")
	}

	_, err = s.GetVersion(ctx, "v", 99)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestMemoryStore_AddVersion(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{
		ID:   "av",
		Name: "Add Version",
		Versions: []LegacyVersion{
			{Version: 1, Template: "original"},
		},
	})

	err := s.AddVersion(ctx, "av", &LegacyVersion{Version: 2, Template: "new version"})
	if err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	p, _ := s.Get(ctx, "av")
	if len(p.Versions) != 2 {
		t.Fatalf("Versions length = %d, want 2", len(p.Versions))
	}

	// Duplicate version should fail.
	err = s.AddVersion(ctx, "av", &LegacyVersion{Version: 2, Template: "dup"})
	if err == nil {
		t.Fatal("expected error for duplicate version")
	}

	// Missing prompt should fail.
	err = s.AddVersion(ctx, "missing", &LegacyVersion{Version: 1, Template: "x"})
	if err == nil {
		t.Fatal("expected error for missing prompt")
	}
}

func TestMemoryStore_SetActiveVersion(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{
		ID:   "sav",
		Name: "Set Active",
		Versions: []LegacyVersion{
			{Version: 1, Template: "v1"},
			{Version: 2, Template: "v2"},
		},
	})

	if err := s.SetActiveVersion(ctx, "sav", 2); err != nil {
		t.Fatalf("SetActiveVersion: %v", err)
	}
	p, _ := s.Get(ctx, "sav")
	if p.ActiveVersion != 2 {
		t.Errorf("ActiveVersion = %d, want 2", p.ActiveVersion)
	}

	// Non-existent version should fail.
	if err := s.SetActiveVersion(ctx, "sav", 99); err == nil {
		t.Fatal("expected error for missing version")
	}

	// Non-existent prompt should fail.
	if err := s.SetActiveVersion(ctx, "missing", 1); err == nil {
		t.Fatal("expected error for missing prompt")
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{ID: "del", Name: "Delete Me"})

	if err := s.Delete(ctx, "del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := s.Get(ctx, "del")
	if err == nil {
		t.Fatal("expected error after delete")
	}

	// Delete non-existent should fail.
	if err := s.Delete(ctx, "del"); err == nil {
		t.Fatal("expected error for missing prompt")
	}
}

func TestMemoryStore_IsolatesCopies(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{
		ID:   "iso",
		Name: "Isolation",
		Versions: []LegacyVersion{
			{Version: 1, Template: "original"},
		},
	})

	got, _ := s.Get(ctx, "iso")
	got.Name = "Modified"
	got.Versions[0].Template = "modified"

	got2, _ := s.Get(ctx, "iso")
	if got2.Name != "Isolation" {
		t.Errorf("mutation leaked: Name = %q", got2.Name)
	}
	if got2.Versions[0].Template != "original" {
		t.Errorf("mutation leaked: Template = %q", got2.Versions[0].Template)
	}
}
