package config

import (
	"testing"
)

func TestNewCSSTransform(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic css transform",
			input: `{
				"type": "css"
			}`,
			expectError: false,
		},
		{
			name: "css transform with precision",
			input: `{
				"type": "css",
				"precision": 2
			}`,
			expectError: false,
		},
		{
			name: "css transform with inline",
			input: `{
				"type": "css",
				"inline": true
			}`,
			expectError: false,
		},
		{
			name: "css transform with version",
			input: `{
				"type": "css",
				"version": 3
			}`,
			expectError: false,
		},
		{
			name: "css transform with all options",
			input: `{
				"type": "css",
				"precision": 3,
				"inline": true,
				"version": 4
			}`,
			expectError: false,
		},
		{
			name: "css transform with content types",
			input: `{
				"type": "css",
				"content_types": ["text/css"]
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "css",
				"precision": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewCSSTransform([]byte(tt.input))
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

			if cfg.GetType() != TransformCSS {
				t.Errorf("expected type %s, got %s", TransformCSS, cfg.GetType())
			}

			cssCfg, ok := cfg.(*CSSTransformConfig)
			if !ok {
				t.Fatal("expected CSSTransformConfig")
			}

			// Verify default content types are set
			if cssCfg.ContentTypes == nil {
				t.Error("expected content types to be set")
			}
		})
	}
}

