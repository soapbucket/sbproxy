package config

import (
	"testing"
)

func TestNewTemplateTransformConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic template transform",
			input: `{
				"type": "template",
				"template": "Hello, {{.name}}!",
				"data": {"name": "World"}
			}`,
			expectError: false,
		},
		{
			name: "template with complex data",
			input: `{
				"type": "template",
				"template": "User: {{.user.name}}, Age: {{.user.age}}",
				"data": {
					"user": {
						"name": "Alice",
						"age": 30
					}
				}
			}`,
			expectError: false,
		},
		{
			name: "template with array data",
			input: `{
				"type": "template",
				"template": "Items: {{range .items}}{{.}}, {{end}}",
				"data": {
					"items": ["apple", "banana", "cherry"]
				}
			}`,
			expectError: false,
		},
		{
			name: "template with null data",
			input: `{
				"type": "template",
				"template": "Static template",
				"data": null
			}`,
			expectError: false,
		},
		{
			name: "template with content types",
			input: `{
				"type": "template",
				"template": "{{.}}",
				"data": "test",
				"content_types": ["text/html"]
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "template",
				"template": 12345
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewTemplateTransformConfig([]byte(tt.input))
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("expected config but got nil")
			}

			if cfg.GetType() != TransformTemplate {
				t.Errorf("expected type %s, got %s", TransformTemplate, cfg.GetType())
			}

			templateCfg, ok := cfg.(*TemplateTransformConfig)
			if !ok {
				t.Fatal("expected TemplateTransformConfig")
			}

			// Verify default content types are set
			if templateCfg.ContentTypes == nil {
				t.Error("expected content types to be set")
			}
		})
	}
}

