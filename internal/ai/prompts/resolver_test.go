package prompts

import (
	"context"
	"testing"
)

func TestResolver_ResolveActiveVersion(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{
		ID:            "greet",
		Name:          "Greeting",
		ActiveVersion: 1,
		Versions: []LegacyVersion{
			{Version: 1, Template: "Hello {{name}}, welcome to {{place}}!", Model: "gpt-4"},
		},
	})

	r := NewResolver(s)
	resolved, err := r.Resolve(ctx, "greet", nil, map[string]string{
		"name":  "Alice",
		"place": "Wonderland",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Content != "Hello Alice, welcome to Wonderland!" {
		t.Errorf("Content = %q, want %q", resolved.Content, "Hello Alice, welcome to Wonderland!")
	}
	if resolved.Model != "gpt-4" {
		t.Errorf("Model = %q, want %q", resolved.Model, "gpt-4")
	}
	if resolved.PromptID != "greet" {
		t.Errorf("PromptID = %q, want %q", resolved.PromptID, "greet")
	}
	if resolved.Version != 1 {
		t.Errorf("Version = %d, want 1", resolved.Version)
	}
}

func TestResolver_ResolveSpecificVersion(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{
		ID:            "multi",
		Name:          "Multi",
		ActiveVersion: 1,
		Versions: []LegacyVersion{
			{Version: 1, Template: "Version one"},
			{Version: 2, Template: "Version two with {{var}}", Model: "claude-3"},
		},
	})

	r := NewResolver(s)
	v := 2
	resolved, err := r.Resolve(ctx, "multi", &v, map[string]string{"var": "value"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Content != "Version two with value" {
		t.Errorf("Content = %q", resolved.Content)
	}
	if resolved.Version != 2 {
		t.Errorf("Version = %d, want 2", resolved.Version)
	}
	if resolved.Model != "claude-3" {
		t.Errorf("Model = %q, want %q", resolved.Model, "claude-3")
	}
}

func TestResolver_ResolveNoVariables(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{
		ID:            "plain",
		Name:          "Plain",
		ActiveVersion: 1,
		Versions: []LegacyVersion{
			{Version: 1, Template: "No variables here"},
		},
	})

	r := NewResolver(s)
	resolved, err := r.Resolve(ctx, "plain", nil, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Content != "No variables here" {
		t.Errorf("Content = %q", resolved.Content)
	}
}

func TestResolver_ResolveNotFound(t *testing.T) {
	s := NewMemoryStore()
	r := NewResolver(s)

	_, err := r.Resolve(context.Background(), "missing", nil, nil)
	if err == nil {
		t.Fatal("expected error for missing prompt")
	}
}

func TestResolver_ResolveMissingVersion(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, &Prompt{
		ID:            "mv",
		Name:          "Missing Version",
		ActiveVersion: 99,
		Versions: []LegacyVersion{
			{Version: 1, Template: "v1"},
		},
	})

	r := NewResolver(s)
	_, err := r.Resolve(ctx, "mv", nil, nil)
	if err == nil {
		t.Fatal("expected error for missing active version")
	}
}

func TestSubstituteVariables(t *testing.T) {
	tests := []struct {
		name     string
		template string
		vars     map[string]string
		want     string
	}{
		{
			name:     "single variable",
			template: "Hello {{name}}",
			vars:     map[string]string{"name": "World"},
			want:     "Hello World",
		},
		{
			name:     "multiple variables",
			template: "{{greeting}} {{name}}!",
			vars:     map[string]string{"greeting": "Hi", "name": "Bob"},
			want:     "Hi Bob!",
		},
		{
			name:     "no variables",
			template: "Static text",
			vars:     nil,
			want:     "Static text",
		},
		{
			name:     "unused variable",
			template: "Hello {{name}}",
			vars:     map[string]string{"name": "World", "unused": "value"},
			want:     "Hello World",
		},
		{
			name:     "unresolved placeholder",
			template: "Hello {{name}} and {{unknown}}",
			vars:     map[string]string{"name": "World"},
			want:     "Hello World and {{unknown}}",
		},
		{
			name:     "repeated variable",
			template: "{{x}} and {{x}}",
			vars:     map[string]string{"x": "val"},
			want:     "val and val",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := substituteVariables(tt.template, tt.vars)
			if got != tt.want {
				t.Errorf("substituteVariables() = %q, want %q", got, tt.want)
			}
		})
	}
}
