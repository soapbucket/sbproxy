package config

import (
	"testing"
)

func TestHTMLTransformAddBeforeEndTag(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		description string
	}{
		{
			name: "html transform with add_before_end_tag true",
			input: `{
				"type": "html",
				"add_to_tags": [{
					"tag": "body",
					"add_before_end_tag": true,
					"content": "<!-- Test -->"
				}]
			}`,
			expectError: false,
			description: "Should work with add_before_end_tag: true",
		},
		{
			name: "html transform with add_before_end_tag false",
			input: `{
				"type": "html",
				"add_to_tags": [{
					"tag": "head",
					"add_before_end_tag": false,
					"content": "<meta name=\"test\">"
				}]
			}`,
			expectError: false,
			description: "Should work with add_before_end_tag: false",
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

			htmlCfg, ok := cfg.(*HTMLTransformConfig)
			if !ok {
				t.Fatal("expected HTMLTransformConfig")
			}

			if len(htmlCfg.AddToTags) == 0 {
				t.Error("expected add_to_tags to be set")
			}

			// Verify the transform was created
			if htmlCfg.tr == nil {
				t.Error("expected transform to be created")
			}
		})
	}
}

func TestOptimizedHTMLTransformAddBeforeEndTag(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		description string
	}{
		{
			name: "optimized_html transform with add_before_end_tag true",
			input: `{
				"type": "optimized_html",
				"add_to_tags": [{
					"tag": "body",
					"add_before_end_tag": true,
					"content": "<!-- Test -->"
				}]
			}`,
			expectError: false,
			description: "Should work with add_before_end_tag: true",
		},
		{
			name: "optimized_html transform with add_before_end_tag false",
			input: `{
				"type": "optimized_html",
				"add_to_tags": [{
					"tag": "head",
					"add_before_end_tag": false,
					"content": "<meta name=\"test\">"
				}]
			}`,
			expectError: false,
			description: "Should work with add_before_end_tag: false",
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

			htmlCfg, ok := cfg.(*OptimizedHTMLTransformConfig)
			if !ok {
				t.Fatal("expected OptimizedHTMLTransformConfig")
			}

			if len(htmlCfg.AddToTags) == 0 {
				t.Error("expected add_to_tags to be set")
			}

			// Verify the transform was created
			if htmlCfg.tr == nil {
				t.Error("expected transform to be created")
			}
		})
	}
}

