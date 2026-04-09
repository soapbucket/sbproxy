package config

import (
	"testing"
)

func TestNewOptimizedHTMLTransform(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic optimized html transform",
			input: `{
				"type": "optimized_html"
			}`,
			expectError: false,
		},
		{
			name: "optimized html transform with format options",
			input: `{
				"type": "optimized_html",
				"format_options": {
					"strip_newlines": true,
					"strip_space": true
				}
			}`,
			expectError: false,
		},
		{
			name: "optimized html transform with remove options",
			input: `{
				"type": "optimized_html",
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
			name: "optimized html transform with optimize and sort",
			input: `{
				"type": "optimized_html",
				"format_options": {
					"optimize_attributes": true,
					"sort_attributes": true
				}
			}`,
			expectError: false,
		},
		{
			name: "optimized html transform with attribute options",
			input: `{
				"type": "optimized_html",
				"attribute_options": {
					"add_unique_ids": true,
					"unique_id_prefix": "opt_",
					"replace_existing": false,
					"use_random_suffix": false
				}
			}`,
			expectError: false,
		},
		{
			name: "optimized html transform with all options",
			input: `{
				"type": "optimized_html",
				"format_options": {
					"strip_newlines": true,
					"strip_space": true,
					"remove_boolean_attributes": true,
					"remove_quotes_from_attributes": true,
					"remove_trailing_slashes": true,
					"strip_comments": true,
					"optimize_attributes": true,
					"sort_attributes": true
				},
				"attribute_options": {
					"add_unique_ids": true,
					"unique_id_prefix": "el_"
				}
			}`,
			expectError: false,
		},
		{
			name: "optimized html transform with content types",
			input: `{
				"type": "optimized_html",
				"content_types": ["text/html"]
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "optimized_html",
				"format_options": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewOptimizedHTMLTransform([]byte(tt.input))
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

			if cfg.GetType() != TransformOptimizedHTML {
				t.Errorf("expected type %s, got %s", TransformOptimizedHTML, cfg.GetType())
			}

			htmlCfg, ok := cfg.(*OptimizedHTMLTransformConfig)
			if !ok {
				t.Fatal("expected OptimizedHTMLTransformConfig")
			}

			// Verify default content types are set
			if htmlCfg.ContentTypes == nil {
				t.Error("expected content types to be set")
			}
		})
	}
}

