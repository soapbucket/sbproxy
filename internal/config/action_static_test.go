package config

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestLoadStaticConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic static config",
			input: `{
				"type": "static",
				"status_code": 200,
				"content_type": "text/plain",
				"body": "Hello, World!"
			}`,
			expectError: false,
		},
		{
			name: "static config with json body",
			input: `{
				"type": "static",
				"status_code": 200,
				"content_type": "application/json",
				"json_body": {"message": "Hello, World!"}
			}`,
			expectError: false,
		},
		{
			name: "static config with base64 body",
			input: `{
				"type": "static",
				"status_code": 200,
				"content_type": "text/plain",
				"body_base64": "SGVsbG8sIFdvcmxkIQ=="
			}`,
			expectError: false,
		},
		{
			name: "static config with custom headers",
			input: `{
				"type": "static",
				"status_code": 404,
				"content_type": "text/html",
				"headers": {
					"X-Custom-Header": "custom-value"
				},
				"body": "<html><body>Not Found</body></html>"
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "static",
				"status_code": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadStaticConfig([]byte(tt.input))
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

			if cfg.GetType() != TypeStatic {
				t.Errorf("expected type %s, got %s", TypeStatic, cfg.GetType())
			}

			// Test transport is set
			if cfg.Transport() == nil {
				t.Error("expected transport to be set")
			}
		})
	}
}

func TestStaticTransportFn(t *testing.T) {
	tests := []struct {
		name               string
		config             *StaticConfig
		expectedStatusCode int
		expectedBody       string
		expectedHeaders    map[string]string
	}{
		{
			name: "simple text response",
			config: &StaticConfig{
				StatusCode:  200,
				ContentType: "text/plain",
				Body:        "Hello, World!",
			},
			expectedStatusCode: 200,
			expectedBody:       "Hello, World!",
			expectedHeaders: map[string]string{
				"Content-Type": "text/plain",
			},
		},
		{
			name: "default status code",
			config: &StaticConfig{
				Body: "Default response",
			},
			expectedStatusCode: 200,
			expectedBody:       "Default response",
			expectedHeaders: map[string]string{
				"Content-Type": "text/plain; charset=utf-8",
			},
		},
		{
			name: "json body",
			config: &StaticConfig{
				StatusCode:  200,
				ContentType: "application/json",
				JSONBody:    json.RawMessage(`{"message":"test"}`),
			},
			expectedStatusCode: 200,
			expectedBody:       `{"message":"test"}`,
			expectedHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			name: "base64 body",
			config: &StaticConfig{
				StatusCode:  200,
				ContentType: "text/plain",
				BodyBase64:  "SGVsbG8sIFdvcmxkIQ==",
			},
			expectedStatusCode: 200,
			expectedBody:       "Hello, World!",
			expectedHeaders: map[string]string{
				"Content-Type": "text/plain",
			},
		},
		{
			name: "custom headers",
			config: &StaticConfig{
				StatusCode:  404,
				ContentType: "text/html",
				Headers: map[string]string{
					"X-Custom-Header": "custom-value",
					"X-Another":       "another-value",
				},
				Body: "Not Found",
			},
			expectedStatusCode: 404,
			expectedBody:       "Not Found",
			expectedHeaders: map[string]string{
				"Content-Type":     "text/html",
				"X-Custom-Header":  "custom-value",
				"X-Another":        "another-value",
			},
		},
		{
			name: "empty body",
			config: &StaticConfig{
				StatusCode:  204,
				ContentType: "text/plain",
			},
			expectedStatusCode: 204,
			expectedBody:       "",
			expectedHeaders: map[string]string{
				"Content-Type": "text/plain",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transportFn := StaticTransportFn(tt.config)
			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := transportFn(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.StatusCode != tt.expectedStatusCode {
				t.Errorf("expected status code %d, got %d", tt.expectedStatusCode, resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read body: %v", err)
			}
			resp.Body.Close()

			if string(body) != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, string(body))
			}

			for key, expectedValue := range tt.expectedHeaders {
				actualValue := resp.Header.Get(key)
				if actualValue != expectedValue {
					t.Errorf("expected header %s=%q, got %q", key, expectedValue, actualValue)
				}
			}
		})
	}
}

