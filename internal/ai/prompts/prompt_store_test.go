package prompts

import (
	"context"
	"testing"
)

func TestMemoryPromptStore_CRUD(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, s *MemoryPromptStore, ctx context.Context)
	}{
		{
			name: "create and get",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				tmpl := &PromptTemplate{
					ID:          "tmpl-1",
					WorkspaceID: "ws-1",
					Name:        "Greeting",
					Description: "A greeting template",
					Messages: []PromptMessage{
						{Role: "system", Content: "You are a helpful assistant."},
						{Role: "user", Content: "Hello {{name}}"},
					},
					Variables: []VariableDef{
						{Name: "name", Required: true},
					},
					CreatedBy: "alice",
				}
				if err := s.Create(ctx, tmpl); err != nil {
					t.Fatalf("Create: %v", err)
				}
				got, err := s.Get(ctx, "tmpl-1")
				if err != nil {
					t.Fatalf("Get: %v", err)
				}
				if got.ID != "tmpl-1" {
					t.Errorf("ID = %q, want %q", got.ID, "tmpl-1")
				}
				if got.WorkspaceID != "ws-1" {
					t.Errorf("WorkspaceID = %q, want %q", got.WorkspaceID, "ws-1")
				}
				if got.Name != "Greeting" {
					t.Errorf("Name = %q, want %q", got.Name, "Greeting")
				}
				if got.Version != 1 {
					t.Errorf("Version = %d, want 1", got.Version)
				}
				if got.CreatedAt.IsZero() {
					t.Error("CreatedAt should be set")
				}
				if got.UpdatedAt.IsZero() {
					t.Error("UpdatedAt should be set")
				}
				if len(got.Messages) != 2 {
					t.Errorf("Messages length = %d, want 2", len(got.Messages))
				}
				if got.CreatedBy != "alice" {
					t.Errorf("CreatedBy = %q, want %q", got.CreatedBy, "alice")
				}
			},
		},
		{
			name: "create duplicate",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{ID: "dup", WorkspaceID: "ws-1", Name: "Dup"})
				if err := s.Create(ctx, &PromptTemplate{ID: "dup", WorkspaceID: "ws-1", Name: "Dup2"}); err == nil {
					t.Fatal("expected error for duplicate, got nil")
				}
			},
		},
		{
			name: "get not found",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				_, err := s.Get(ctx, "missing")
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			},
		},
		{
			name: "delete",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{ID: "del", WorkspaceID: "ws-1", Name: "Delete"})
				if err := s.Delete(ctx, "del"); err != nil {
					t.Fatalf("Delete: %v", err)
				}
				_, err := s.Get(ctx, "del")
				if err == nil {
					t.Fatal("expected error after delete")
				}
			},
		},
		{
			name: "delete not found",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				if err := s.Delete(ctx, "missing"); err == nil {
					t.Fatal("expected error for missing prompt")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryPromptStore()
			tt.fn(t, s, context.Background())
		})
	}
}

func TestMemoryPromptStore_Versioning(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, s *MemoryPromptStore, ctx context.Context)
	}{
		{
			name: "update creates new version",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{
					ID:          "v",
					WorkspaceID: "ws-1",
					Name:        "Versioned",
					Messages:    []PromptMessage{{Role: "user", Content: "v1 content"}},
				})
				err := s.Update(ctx, &PromptTemplate{
					ID:       "v",
					Name:     "Versioned Updated",
					Messages: []PromptMessage{{Role: "user", Content: "v2 content"}},
				})
				if err != nil {
					t.Fatalf("Update: %v", err)
				}
				got, _ := s.Get(ctx, "v")
				if got.Version != 2 {
					t.Errorf("Version = %d, want 2", got.Version)
				}
				if got.Name != "Versioned Updated" {
					t.Errorf("Name = %q, want %q", got.Name, "Versioned Updated")
				}
				if got.Messages[0].Content != "v2 content" {
					t.Errorf("Content = %q, want %q", got.Messages[0].Content, "v2 content")
				}
			},
		},
		{
			name: "list versions",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{
					ID: "lv", WorkspaceID: "ws-1", Name: "ListVersions",
					Messages: []PromptMessage{{Role: "user", Content: "v1"}},
				})
				s.Update(ctx, &PromptTemplate{
					ID: "lv", Messages: []PromptMessage{{Role: "user", Content: "v2"}},
				})
				s.Update(ctx, &PromptTemplate{
					ID: "lv", Messages: []PromptMessage{{Role: "user", Content: "v3"}},
				})
				versions, err := s.ListVersions(ctx, "lv")
				if err != nil {
					t.Fatalf("ListVersions: %v", err)
				}
				if len(versions) != 3 {
					t.Fatalf("versions length = %d, want 3", len(versions))
				}
				if versions[0].Version != 1 {
					t.Errorf("first version = %d, want 1", versions[0].Version)
				}
				if versions[2].Version != 3 {
					t.Errorf("last version = %d, want 3", versions[2].Version)
				}
			},
		},
		{
			name: "get specific version",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{
					ID: "gv", WorkspaceID: "ws-1", Name: "GetVersion",
					Messages: []PromptMessage{{Role: "user", Content: "original"}},
				})
				s.Update(ctx, &PromptTemplate{
					ID: "gv", Messages: []PromptMessage{{Role: "user", Content: "updated"}},
				})
				v1, err := s.GetVersion(ctx, "gv", 1)
				if err != nil {
					t.Fatalf("GetVersion(1): %v", err)
				}
				if v1.Messages[0].Content != "original" {
					t.Errorf("v1 content = %q, want %q", v1.Messages[0].Content, "original")
				}
				v2, err := s.GetVersion(ctx, "gv", 2)
				if err != nil {
					t.Fatalf("GetVersion(2): %v", err)
				}
				if v2.Messages[0].Content != "updated" {
					t.Errorf("v2 content = %q, want %q", v2.Messages[0].Content, "updated")
				}
				_, err = s.GetVersion(ctx, "gv", 99)
				if err == nil {
					t.Fatal("expected error for missing version")
				}
			},
		},
		{
			name: "get version not found prompt",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				_, err := s.GetVersion(ctx, "missing", 1)
				if err == nil {
					t.Fatal("expected error for missing prompt")
				}
			},
		},
		{
			name: "list versions not found",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				_, err := s.ListVersions(ctx, "missing")
				if err == nil {
					t.Fatal("expected error for missing prompt")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryPromptStore()
			tt.fn(t, s, context.Background())
		})
	}
}

func TestMemoryPromptStore_Rollback(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, s *MemoryPromptStore, ctx context.Context)
	}{
		{
			name: "rollback creates new version from target",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{
					ID: "rb", WorkspaceID: "ws-1", Name: "Rollback",
					Messages: []PromptMessage{{Role: "user", Content: "v1 original"}},
				})
				s.Update(ctx, &PromptTemplate{
					ID: "rb", Messages: []PromptMessage{{Role: "user", Content: "v2 changed"}},
				})
				// Rollback to version 1.
				if err := s.Rollback(ctx, "rb", 1); err != nil {
					t.Fatalf("Rollback: %v", err)
				}
				got, _ := s.Get(ctx, "rb")
				// Should be version 3 (new version created from v1 content).
				if got.Version != 3 {
					t.Errorf("Version = %d, want 3", got.Version)
				}
				if got.Messages[0].Content != "v1 original" {
					t.Errorf("Content = %q, want %q", got.Messages[0].Content, "v1 original")
				}
				// Should have 3 versions in history.
				versions, _ := s.ListVersions(ctx, "rb")
				if len(versions) != 3 {
					t.Errorf("versions count = %d, want 3", len(versions))
				}
			},
		},
		{
			name: "rollback missing version",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{ID: "rb2", WorkspaceID: "ws-1", Name: "Rollback2"})
				if err := s.Rollback(ctx, "rb2", 99); err == nil {
					t.Fatal("expected error for missing version")
				}
			},
		},
		{
			name: "rollback missing prompt",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				if err := s.Rollback(ctx, "missing", 1); err == nil {
					t.Fatal("expected error for missing prompt")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryPromptStore()
			tt.fn(t, s, context.Background())
		})
	}
}

func TestMemoryPromptStore_Labels(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, s *MemoryPromptStore, ctx context.Context)
	}{
		{
			name: "set and use label",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{
					ID: "lb", WorkspaceID: "ws-1", Name: "Labeled",
					Messages: []PromptMessage{{Role: "user", Content: "v1"}},
				})
				s.Update(ctx, &PromptTemplate{
					ID: "lb", Messages: []PromptMessage{{Role: "user", Content: "v2"}},
				})
				s.Update(ctx, &PromptTemplate{
					ID: "lb", Messages: []PromptMessage{{Role: "user", Content: "v3"}},
				})
				// Label version 2 as "production".
				if err := s.SetLabel(ctx, "lb", "production", 2); err != nil {
					t.Fatalf("SetLabel: %v", err)
				}
				got, _ := s.Get(ctx, "lb")
				if got.Labels["production"] != "2" {
					t.Errorf("production label = %q, want %q", got.Labels["production"], "2")
				}
				// GetByLabel should return v2 content.
				labeled, err := s.GetByLabel(ctx, "ws-1", "Labeled", "production")
				if err != nil {
					t.Fatalf("GetByLabel: %v", err)
				}
				if labeled.Messages[0].Content != "v2" {
					t.Errorf("labeled content = %q, want %q", labeled.Messages[0].Content, "v2")
				}
			},
		},
		{
			name: "set label missing version",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{ID: "lb2", WorkspaceID: "ws-1", Name: "L2"})
				if err := s.SetLabel(ctx, "lb2", "prod", 99); err == nil {
					t.Fatal("expected error for missing version")
				}
			},
		},
		{
			name: "set label missing prompt",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				if err := s.SetLabel(ctx, "missing", "prod", 1); err == nil {
					t.Fatal("expected error for missing prompt")
				}
			},
		},
		{
			name: "get by label missing label",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{ID: "lb3", WorkspaceID: "ws-1", Name: "L3"})
				_, err := s.GetByLabel(ctx, "ws-1", "L3", "nonexistent")
				if err == nil {
					t.Fatal("expected error for missing label")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryPromptStore()
			tt.fn(t, s, context.Background())
		})
	}
}

func TestMemoryPromptStore_ListByWorkspace(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, s *MemoryPromptStore, ctx context.Context)
	}{
		{
			name: "list by workspace with pagination",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{ID: "a", WorkspaceID: "ws-1", Name: "Alpha"})
				s.Create(ctx, &PromptTemplate{ID: "b", WorkspaceID: "ws-1", Name: "Beta"})
				s.Create(ctx, &PromptTemplate{ID: "c", WorkspaceID: "ws-2", Name: "Charlie"})
				s.Create(ctx, &PromptTemplate{ID: "d", WorkspaceID: "ws-1", Name: "Delta"})

				// List ws-1 only.
				list, err := s.List(ctx, "ws-1", 100, 0)
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				if len(list) != 3 {
					t.Errorf("list length = %d, want 3", len(list))
				}

				// Pagination: limit 2, offset 0.
				list, err = s.List(ctx, "ws-1", 2, 0)
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				if len(list) != 2 {
					t.Errorf("list length = %d, want 2", len(list))
				}

				// Pagination: limit 2, offset 2.
				list, err = s.List(ctx, "ws-1", 2, 2)
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				if len(list) != 1 {
					t.Errorf("list length = %d, want 1", len(list))
				}

				// Offset beyond results.
				list, err = s.List(ctx, "ws-1", 100, 100)
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				if list != nil {
					t.Errorf("list should be nil for offset beyond results, got %d", len(list))
				}
			},
		},
		{
			name: "list all workspaces",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{ID: "a", WorkspaceID: "ws-1", Name: "Alpha"})
				s.Create(ctx, &PromptTemplate{ID: "b", WorkspaceID: "ws-2", Name: "Beta"})

				list, err := s.List(ctx, "", 100, 0)
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				if len(list) != 2 {
					t.Errorf("list length = %d, want 2", len(list))
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryPromptStore()
			tt.fn(t, s, context.Background())
		})
	}
}

func TestMemoryPromptStore_GetByName(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, s *MemoryPromptStore, ctx context.Context)
	}{
		{
			name: "get by name found",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{
					ID: "gbn", WorkspaceID: "ws-1", Name: "Greeting",
					Messages: []PromptMessage{{Role: "user", Content: "Hello"}},
				})
				got, err := s.GetByName(ctx, "ws-1", "Greeting")
				if err != nil {
					t.Fatalf("GetByName: %v", err)
				}
				if got.ID != "gbn" {
					t.Errorf("ID = %q, want %q", got.ID, "gbn")
				}
			},
		},
		{
			name: "get by name not found",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				_, err := s.GetByName(ctx, "ws-1", "Missing")
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			},
		},
		{
			name: "get by name wrong workspace",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{ID: "gbn2", WorkspaceID: "ws-1", Name: "Greeting"})
				_, err := s.GetByName(ctx, "ws-2", "Greeting")
				if err == nil {
					t.Fatal("expected error for wrong workspace")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryPromptStore()
			tt.fn(t, s, context.Background())
		})
	}
}

func TestMemoryPromptStore_GetByLabel(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T, s *MemoryPromptStore, ctx context.Context)
	}{
		{
			name: "get by label found",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{
					ID: "gbl", WorkspaceID: "ws-1", Name: "Greeting",
					Messages: []PromptMessage{{Role: "user", Content: "v1"}},
				})
				s.Update(ctx, &PromptTemplate{
					ID: "gbl", Messages: []PromptMessage{{Role: "user", Content: "v2"}},
				})
				s.SetLabel(ctx, "gbl", "production", 1)

				got, err := s.GetByLabel(ctx, "ws-1", "Greeting", "production")
				if err != nil {
					t.Fatalf("GetByLabel: %v", err)
				}
				if got.Messages[0].Content != "v1" {
					t.Errorf("Content = %q, want %q", got.Messages[0].Content, "v1")
				}
			},
		},
		{
			name: "get by label wrong workspace",
			fn: func(t *testing.T, s *MemoryPromptStore, ctx context.Context) {
				s.Create(ctx, &PromptTemplate{ID: "gbl2", WorkspaceID: "ws-1", Name: "Greeting"})
				s.SetLabel(ctx, "gbl2", "production", 1)
				_, err := s.GetByLabel(ctx, "ws-2", "Greeting", "production")
				if err == nil {
					t.Fatal("expected error for wrong workspace")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryPromptStore()
			tt.fn(t, s, context.Background())
		})
	}
}

func TestMemoryPromptStore_IsolatesCopies(t *testing.T) {
	s := NewMemoryPromptStore()
	ctx := context.Background()

	s.Create(ctx, &PromptTemplate{
		ID: "iso", WorkspaceID: "ws-1", Name: "Isolation",
		Messages: []PromptMessage{{Role: "user", Content: "original"}},
	})

	got, _ := s.Get(ctx, "iso")
	got.Name = "Modified"
	got.Messages[0].Content = "mutated"

	got2, _ := s.Get(ctx, "iso")
	if got2.Name != "Isolation" {
		t.Errorf("mutation leaked: Name = %q", got2.Name)
	}
	if got2.Messages[0].Content != "original" {
		t.Errorf("mutation leaked: Content = %q", got2.Messages[0].Content)
	}
}

func TestMemoryPromptStore_UpdateNotFound(t *testing.T) {
	s := NewMemoryPromptStore()
	err := s.Update(context.Background(), &PromptTemplate{ID: "missing", Name: "X"})
	if err == nil {
		t.Fatal("expected error for missing prompt")
	}
}
