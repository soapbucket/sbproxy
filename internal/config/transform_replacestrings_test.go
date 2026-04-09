package config

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestNewReplaceStringsTransform(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic replace strings transform",
			input: `{
				"type": "replace_strings",
				"replace_strings": {
					"replacements": [
						{
							"find": "old",
							"replace": "new"
						}
					]
				}
			}`,
			expectError: false,
		},
		{
			name: "multiple replacements",
			input: `{
				"type": "replace_strings",
				"replace_strings": {
					"replacements": [
						{
							"find": "foo",
							"replace": "bar"
						},
						{
							"find": "hello",
							"replace": "goodbye"
						}
					]
				}
			}`,
			expectError: false,
		},
		{
			name: "empty replacements",
			input: `{
				"type": "replace_strings",
				"replace_strings": {
					"replacements": []
				}
			}`,
			expectError: false,
		},
		{
			name: "replace strings with content types",
			input: `{
				"type": "replace_strings",
				"content_types": ["text/html", "text/plain"],
				"replace_strings": {
					"replacements": [
						{
							"find": "old",
							"replace": "new"
						}
					]
				}
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "replace_strings",
				"replace_strings": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewReplaceStringsTransform([]byte(tt.input))
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

			if cfg.GetType() != TransformReplaceStrings {
				t.Errorf("expected type %s, got %s", TransformReplaceStrings, cfg.GetType())
			}

			replaceCfg, ok := cfg.(*ReplaceStringsTransformConfig)
			if !ok {
				t.Fatal("expected ReplaceStringsTransformConfig")
			}

			// Verify default content types are set if not specified
			if replaceCfg.ContentTypes == nil {
				t.Error("expected content types to be set")
			}
		})
	}
}

func TestReplaceStringsTransformApply(t *testing.T) {
	t.Run("performs single replacement", func(t *testing.T) {
		input := "Hello, old world!"
		expected := "Hello, new world!"

		transform, err := NewReplaceStringsTransform([]byte(`{
			"type": "replace_strings",
			"replace_strings": {
				"replacements": [
					{
						"find": "old",
						"replace": "new"
					}
				]
			}
		}`))
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
		resp.Header.Set("Content-Type", "text/html")

		err = transform.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != expected {
			t.Errorf("expected %q, got %q", expected, string(body))
		}
	})

	t.Run("performs multiple replacements", func(t *testing.T) {
		input := "Hello, foo! How are you, bar?"
		expected := "Hello, baz! How are you, qux?"

		transform, err := NewReplaceStringsTransform([]byte(`{
			"type": "replace_strings",
			"replace_strings": {
				"replacements": [
					{
						"find": "foo",
						"replace": "baz"
					},
					{
						"find": "bar",
						"replace": "qux"
					}
				]
			}
		}`))
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
		resp.Header.Set("Content-Type", "text/html")

		err = transform.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != expected {
			t.Errorf("expected %q, got %q", expected, string(body))
		}
	})

	t.Run("skips when no replacements", func(t *testing.T) {
		input := "Hello, world!"

		transform, err := NewReplaceStringsTransform([]byte(`{
			"type": "replace_strings",
			"replace_strings": {
				"replacements": []
			}
		}`))
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
		resp.Header.Set("Content-Type", "text/html")

		err = transform.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != input {
			t.Errorf("expected unchanged body %q, got %q", input, string(body))
		}
	})

	t.Run("skips when disabled", func(t *testing.T) {
		input := "Hello, old world!"
		cfg := &ReplaceStringsTransformConfig{
			ReplaceStringTransform: ReplaceStringTransform{
				BaseTransform: BaseTransform{
					TransformType: TransformReplaceStrings,
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
		resp.Header.Set("Content-Type", "text/html")

		err := cfg.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != input {
			t.Errorf("expected unchanged body %q, got %q", input, string(body))
		}
	})
}

