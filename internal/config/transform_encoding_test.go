package config

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestNewEncodingTransform(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic encoding transform",
			input: `{
				"type": "encoding"
			}`,
			expectError: false,
		},
		{
			name: "encoding transform with disabled flag",
			input: `{
				"type": "encoding",
				"disabled": true
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "encoding",
				"disabled": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewEncodingTransform([]byte(tt.input))
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

			if cfg.GetType() != TransformEncoding {
				t.Errorf("expected type %s, got %s", TransformEncoding, cfg.GetType())
			}
		})
	}
}

func TestNewDefaultEncodingTransform(t *testing.T) {
	// Both FixEncoding and FixContentType are always enabled
	// Parameters are ignored but kept for backward compatibility
	t.Run("always enabled", func(t *testing.T) {
		cfg, err := NewDefaultEncodingTransform(false, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg == nil {
			t.Fatal("expected config but got nil")
		}

		encodingCfg, ok := cfg.(*EncodingTransformConfig)
		if !ok {
			t.Fatal("expected EncodingTransformConfig")
		}

		if encodingCfg.trEncoding == nil {
			t.Error("expected trEncoding to be set")
		}

		if encodingCfg.trContentType == nil {
			t.Error("expected trContentType to be set")
		}
	})
}

func TestEncodingTransformInit(t *testing.T) {
	// Both FixEncoding and FixContentType are always enabled
	t.Run("always enabled", func(t *testing.T) {
		transform := &EncodingTransformConfig{
			BaseTransform: BaseTransform{
				TransformType: TransformEncoding,
			},
		}

		config := &Config{}
		err := transform.Init(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if transform.trEncoding == nil {
			t.Error("expected trEncoding to be set")
		}

		if transform.trContentType == nil {
			t.Error("expected trContentType to be set")
		}
	})
}

func TestEncodingTransformApply(t *testing.T) {
	t.Run("decompresses gzip response", func(t *testing.T) {
		// Create a gzip compressed body
		originalBody := []byte("Hello, World!")
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		_, err := gzipWriter.Write(originalBody)
		if err != nil {
			t.Fatalf("failed to write gzip: %v", err)
		}
		gzipWriter.Close()

	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(&buf),
		Request: &http.Request{
			URL: &url.URL{Path: "/test"},
		},
	}
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Set("Content-Type", "text/plain")

		transform, err := NewDefaultEncodingTransform(false, false)
		if err != nil {
			t.Fatalf("failed to create transform: %v", err)
		}

		err = transform.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Body should be decompressed
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(body) != string(originalBody) {
			t.Errorf("expected body %q, got %q", string(originalBody), string(body))
		}
	})

	t.Run("skips when disabled", func(t *testing.T) {
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader([]byte("test"))),
			Request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
		}

		transform := &EncodingTransformConfig{
			BaseTransform: BaseTransform{
				TransformType: TransformEncoding,
				Disabled:      true,
			},
		}

		err := transform.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

