package config

import (
	"testing"
)

func TestNewJavascriptTransform(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic javascript transform",
			input: `{
				"type": "javascript"
			}`,
			expectError: false,
		},
		{
			name: "javascript transform with number precision",
			input: `{
				"type": "javascript",
				"number_precision": 2
			}`,
			expectError: false,
		},
		{
			name: "javascript transform with change variable names",
			input: `{
				"type": "javascript",
				"change_variable_names": true
			}`,
			expectError: false,
		},
		{
			name: "javascript transform with supported version",
			input: `{
				"type": "javascript",
				"supported_version": 2015
			}`,
			expectError: false,
		},
		{
			name: "javascript transform with all options",
			input: `{
				"type": "javascript",
				"number_precision": 3,
				"change_variable_names": true,
				"supported_version": 2020
			}`,
			expectError: false,
		},
		{
			name: "javascript transform with content types",
			input: `{
				"type": "javascript",
				"content_types": ["text/javascript", "application/javascript"]
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "javascript",
				"number_precision": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewJavascriptTransform([]byte(tt.input))
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

			if cfg.GetType() != TransformJavascript {
				t.Errorf("expected type %s, got %s", TransformJavascript, cfg.GetType())
			}

			jsCfg, ok := cfg.(*JavascriptTransformConfig)
			if !ok {
				t.Fatal("expected JavascriptTransformConfig")
			}

			// Verify default content types are set
			if jsCfg.ContentTypes == nil {
				t.Error("expected content types to be set")
			}
		})
	}
}

