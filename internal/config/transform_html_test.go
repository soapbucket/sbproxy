package config

import (
	"testing"
)

func TestNewHTMLTransform(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic html transform",
			input: `{
				"type": "html"
			}`,
			expectError: false,
		},
		{
			name: "html transform with format options",
			input: `{
				"type": "html",
				"format_options": {
					"strip_newlines": true,
					"strip_space": true,
					"lowercase_tags": true,
					"lowercase_attributes": true
				}
			}`,
			expectError: false,
		},
		{
			name: "html transform with remove options",
			input: `{
				"type": "html",
				"format_options": {
					"remove_boolean_attributes": true,
					"remove_quotes_from_attributes": true,
					"remove_trailing_slashes": true,
					"strip_comments": true
				}
			}`,
			expectError: false,
		},
		{
			name: "html transform with optimize and sort attributes",
			input: `{
				"type": "html",
				"format_options": {
					"optimize_attributes": true,
					"sort_attributes": true
				}
			}`,
			expectError: false,
		},
		{
			name: "html transform with attribute options",
			input: `{
				"type": "html",
				"attribute_options": {
					"add_unique_ids": true,
					"unique_id_prefix": "el_",
					"replace_existing": true,
					"use_random_suffix": true
				}
			}`,
			expectError: false,
		},
		{
			name: "html transform with content types",
			input: `{
				"type": "html",
				"content_types": ["text/html"]
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "html",
				"format_options": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewHTMLTransform([]byte(tt.input))
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

			if cfg.GetType() != TransformHTML {
				t.Errorf("expected type %s, got %s", TransformHTML, cfg.GetType())
			}

			htmlCfg, ok := cfg.(*HTMLTransformConfig)
			if !ok {
				t.Fatal("expected HTMLTransformConfig")
			}

			// Verify default content types are set
			if htmlCfg.ContentTypes == nil {
				t.Error("expected content types to be set")
			}
		})
	}
}

