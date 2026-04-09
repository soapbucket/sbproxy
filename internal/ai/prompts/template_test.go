package prompts

import (
	"testing"
)

func TestTemplateRenderer_Render(t *testing.T) {
	tests := []struct {
		name      string
		template  *PromptTemplate
		variables map[string]string
		want      []RenderedMessage
		wantErr   bool
	}{
		{
			name: "simple variable substitution",
			template: &PromptTemplate{
				Messages: []PromptMessage{
					{Role: "system", Content: "You are a helpful {{role}}."},
					{Role: "user", Content: "Hello, my name is {{name}}."},
				},
				Variables: []VariableDef{
					{Name: "role", Required: true},
					{Name: "name", Required: true},
				},
			},
			variables: map[string]string{"role": "assistant", "name": "Alice"},
			want: []RenderedMessage{
				{Role: "system", Content: "You are a helpful assistant."},
				{Role: "user", Content: "Hello, my name is Alice."},
			},
		},
		{
			name: "missing required variable",
			template: &PromptTemplate{
				Messages: []PromptMessage{
					{Role: "user", Content: "Hello {{name}}"},
				},
				Variables: []VariableDef{
					{Name: "name", Required: true},
				},
			},
			variables: map[string]string{},
			wantErr:   true,
		},
		{
			name: "default value applied",
			template: &PromptTemplate{
				Messages: []PromptMessage{
					{Role: "user", Content: "Language: {{language}}"},
				},
				Variables: []VariableDef{
					{Name: "language", Required: false, Default: "English"},
				},
			},
			variables: map[string]string{},
			want: []RenderedMessage{
				{Role: "user", Content: "Language: English"},
			},
		},
		{
			name: "override default value",
			template: &PromptTemplate{
				Messages: []PromptMessage{
					{Role: "user", Content: "Language: {{language}}"},
				},
				Variables: []VariableDef{
					{Name: "language", Required: false, Default: "English"},
				},
			},
			variables: map[string]string{"language": "French"},
			want: []RenderedMessage{
				{Role: "user", Content: "Language: French"},
			},
		},
		{
			name: "required variable with default not required in input",
			template: &PromptTemplate{
				Messages: []PromptMessage{
					{Role: "user", Content: "Hello {{name}}"},
				},
				Variables: []VariableDef{
					{Name: "name", Required: true, Default: "World"},
				},
			},
			variables: map[string]string{},
			want: []RenderedMessage{
				{Role: "user", Content: "Hello World"},
			},
		},
		{
			name: "no variables defined",
			template: &PromptTemplate{
				Messages: []PromptMessage{
					{Role: "system", Content: "You are helpful."},
					{Role: "user", Content: "What is the weather?"},
				},
			},
			variables: nil,
			want: []RenderedMessage{
				{Role: "system", Content: "You are helpful."},
				{Role: "user", Content: "What is the weather?"},
			},
		},
		{
			name: "multiple messages with same variable",
			template: &PromptTemplate{
				Messages: []PromptMessage{
					{Role: "system", Content: "Respond in {{language}}."},
					{Role: "user", Content: "Say hello in {{language}}."},
				},
				Variables: []VariableDef{
					{Name: "language", Required: true},
				},
			},
			variables: map[string]string{"language": "Spanish"},
			want: []RenderedMessage{
				{Role: "system", Content: "Respond in Spanish."},
				{Role: "user", Content: "Say hello in Spanish."},
			},
		},
	}

	renderer := NewTemplateRenderer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := renderer.Render(tt.template, tt.variables)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d messages, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i].Role != tt.want[i].Role {
					t.Errorf("message[%d].Role = %q, want %q", i, got[i].Role, tt.want[i].Role)
				}
				if got[i].Content != tt.want[i].Content {
					t.Errorf("message[%d].Content = %q, want %q", i, got[i].Content, tt.want[i].Content)
				}
			}
		})
	}
}

func TestValidateVariables(t *testing.T) {
	tests := []struct {
		name      string
		template  *PromptTemplate
		variables map[string]string
		wantErr   bool
	}{
		{
			name: "all required present",
			template: &PromptTemplate{
				Variables: []VariableDef{
					{Name: "a", Required: true},
					{Name: "b", Required: true},
				},
			},
			variables: map[string]string{"a": "1", "b": "2"},
			wantErr:   false,
		},
		{
			name: "missing required",
			template: &PromptTemplate{
				Variables: []VariableDef{
					{Name: "a", Required: true},
					{Name: "b", Required: true},
				},
			},
			variables: map[string]string{"a": "1"},
			wantErr:   true,
		},
		{
			name: "optional missing is ok",
			template: &PromptTemplate{
				Variables: []VariableDef{
					{Name: "a", Required: true},
					{Name: "b", Required: false},
				},
			},
			variables: map[string]string{"a": "1"},
			wantErr:   false,
		},
		{
			name: "required with default is ok",
			template: &PromptTemplate{
				Variables: []VariableDef{
					{Name: "a", Required: true, Default: "fallback"},
				},
			},
			variables: map[string]string{},
			wantErr:   false,
		},
		{
			name:      "no variables defined",
			template:  &PromptTemplate{},
			variables: nil,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVariables(tt.template, tt.variables)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestExtractVariables(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "single variable",
			content: "Hello {{name}}",
			want:    []string{"name"},
		},
		{
			name:    "multiple variables",
			content: "{{greeting}} {{name}}, welcome to {{place}}",
			want:    []string{"greeting", "name", "place"},
		},
		{
			name:    "duplicate variable",
			content: "{{x}} and {{x}} and {{y}}",
			want:    []string{"x", "y"},
		},
		{
			name:    "no variables",
			content: "Plain text without any variables",
			want:    nil,
		},
		{
			name:    "variables with spaces",
			content: "{{ name }} and {{  role  }}",
			want:    []string{"name", "role"},
		},
		{
			name:    "underscore in variable name",
			content: "{{first_name}} {{last_name}}",
			want:    []string{"first_name", "last_name"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractVariables(tt.content)
			if len(got) != len(tt.want) {
				t.Fatalf("ExtractVariables() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestTemplateRenderer_MustacheRendering(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		variables map[string]string
		want      string
	}{
		{
			name:      "basic substitution",
			content:   "Hello {{name}}!",
			variables: map[string]string{"name": "World"},
			want:      "Hello World!",
		},
		{
			name:      "multiple occurrences",
			content:   "{{x}} + {{x}} = 2{{x}}",
			variables: map[string]string{"x": "a"},
			want:      "a + a = 2a",
		},
		{
			name:      "html entities not escaped for triple braces",
			content:   "{{{html}}}",
			variables: map[string]string{"html": "<b>bold</b>"},
			want:      "<b>bold</b>",
		},
	}
	renderer := NewTemplateRenderer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &PromptTemplate{
				Messages: []PromptMessage{{Role: "user", Content: tt.content}},
			}
			// Add all variables as non-required.
			for k := range tt.variables {
				tmpl.Variables = append(tmpl.Variables, VariableDef{Name: k})
			}
			got, err := renderer.Render(tmpl, tt.variables)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if got[0].Content != tt.want {
				t.Errorf("Content = %q, want %q", got[0].Content, tt.want)
			}
		})
	}
}
