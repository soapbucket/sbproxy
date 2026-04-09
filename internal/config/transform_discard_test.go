package config

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestNewDiscardTransform(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "discard first 10 bytes",
			input: `{
				"type": "discard",
				"bytes": 10
			}`,
			expectError: false,
		},
		{
			name: "discard 100 bytes",
			input: `{
				"type": "discard",
				"bytes": 100
			}`,
			expectError: false,
		},
		{
			name: "discard 0 bytes",
			input: `{
				"type": "discard",
				"bytes": 0
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "discard",
				"bytes": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewDiscardTransform([]byte(tt.input))
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

			if cfg.GetType() != TransformDiscard {
				t.Errorf("expected type %s, got %s", TransformDiscard, cfg.GetType())
			}
		})
	}
}

func TestDiscardTransformApply(t *testing.T) {
	t.Run("discards specified bytes", func(t *testing.T) {
		input := "0123456789ABCDEFGHIJ"
		expected := "ABCDEFGHIJ"

		transform, err := NewDiscardTransform([]byte(`{
			"type": "discard",
			"bytes": 10
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
		resp.Header.Set("Content-Type", "text/plain")

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

	t.Run("discards more bytes than available", func(t *testing.T) {
		input := "short"

		transform, err := NewDiscardTransform([]byte(`{
			"type": "discard",
			"bytes": 100
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
		resp.Header.Set("Content-Type", "text/plain")

		err = transform.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		// Should discard all and return empty
		if len(body) != 0 {
			t.Errorf("expected empty body, got %q", string(body))
		}
	})

	t.Run("discards zero bytes", func(t *testing.T) {
		input := "Hello, world!"

		transform, err := NewDiscardTransform([]byte(`{
			"type": "discard",
			"bytes": 0
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
		resp.Header.Set("Content-Type", "text/plain")

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
		input := "0123456789"
		cfg := &DiscardTransformConfig{
			DiscardTransform: DiscardTransform{
				BaseTransform: BaseTransform{
					TransformType: TransformDiscard,
					Disabled:      true,
				},
				Bytes: 5,
			},
		}

		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader([]byte(input))),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}
		resp.Header.Set("Content-Type", "text/plain")

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

