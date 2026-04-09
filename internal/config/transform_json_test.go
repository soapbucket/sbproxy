package config

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestNewJSONTransform(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic json transform",
			input: `{
				"type": "json"
			}`,
			expectError: false,
		},
		{
			name: "json transform with remove empty objects",
			input: `{
				"type": "json",
				"remove_empty_objects": true
			}`,
			expectError: false,
		},
		{
			name: "json transform with remove empty arrays",
			input: `{
				"type": "json",
				"remove_empty_arrays": true
			}`,
			expectError: false,
		},
		{
			name: "json transform with rules",
			input: `{
				"type": "json",
				"rules": [
					{
						"path": "data.id",
						"value": 123
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "json transform with pretty print",
			input: `{
				"type": "json",
				"pretty_print": true
			}`,
			expectError: false,
		},
		{
			name: "json transform with all cleanup options",
			input: `{
				"type": "json",
				"remove_empty_objects": true,
				"remove_empty_arrays": true,
				"remove_false_booleans": true,
				"remove_empty_strings": true,
				"remove_zero_numbers": true
			}`,
			expectError: false,
		},
		{
			name: "json transform with content types",
			input: `{
				"type": "json",
				"content_types": ["application/json", "application/ld+json"]
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "json",
				"remove_empty_objects": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewJSONTransform([]byte(tt.input))
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

			if cfg.GetType() != TransformJSON {
				t.Errorf("expected type %s, got %s", TransformJSON, cfg.GetType())
			}

			jsonCfg, ok := cfg.(*JSONTransformConfig)
			if !ok {
				t.Fatal("expected JSONTransformConfig")
			}

			// Verify default content types are set
			if jsonCfg.ContentTypes == nil {
				t.Error("expected content types to be set")
			}
		})
	}
}

func TestJSONTransformApply(t *testing.T) {
	t.Run("removes empty objects", func(t *testing.T) {
		input := `{"data": {"name": "test", "empty": {}}, "another": {}}`
		expected := `{"data":{"name":"test"}}`

		// Need to initialize with transform
		transform, err := NewJSONTransform([]byte(`{"type":"json","remove_empty_objects":true}`))
		if err != nil {
			t.Fatalf("failed to create transform: %v", err)
		}

		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader([]byte(input))),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "application/json")

		err = transform.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		// Normalize whitespace for comparison
		result := strings.TrimSpace(string(body))
		expected = strings.TrimSpace(expected)

		if result != expected {
			t.Errorf("expected %q, got %q", expected, result)
		}
	})

	t.Run("skips when disabled", func(t *testing.T) {
		input := `{"test": "data"}`
		cfg := &JSONTransformConfig{
			JSONTransform: JSONTransform{
				BaseTransform: BaseTransform{
					TransformType: TransformJSON,
					Disabled:      true,
				},
			},
		}

		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader([]byte(input))),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "application/json")

		err := cfg.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != input {
			t.Errorf("expected body unchanged, got %q", string(body))
		}
	})

	t.Run("skips when content type doesn't match", func(t *testing.T) {
		input := `{"test": "data"}`
		transform, err := NewJSONTransform([]byte(`{"type":"json","remove_empty_objects":true}`))
		if err != nil {
			t.Fatalf("failed to create transform: %v", err)
		}

		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader([]byte(input))),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/html") // Wrong content type

		err = transform.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

