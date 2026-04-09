package config

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestLoadEchoConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic echo config",
			input: `{
				"type": "echo"
			}`,
			expectError: false,
		},
		{
			name: "echo config with include context",
			input: `{
				"type": "echo",
				"include_context": true
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "echo",
				"include_context": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadEchoConfig([]byte(tt.input))
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

			if cfg.GetType() != TypeEcho {
				t.Errorf("expected type %s, got %s", TypeEcho, cfg.GetType())
			}

			// Test transport is set
			if cfg.Transport() == nil {
				t.Error("expected transport to be set")
			}
		})
	}
}

func TestEchoTransportFn(t *testing.T) {
	tests := []struct {
		name        string
		config      *EchoActionConfig
		method      string
		url         string
		body        string
		headers     map[string]string
		expectError bool
	}{
		{
			name: "simple GET request",
			config: &EchoActionConfig{
				EchoConfig: EchoConfig{
					IncludeContext: false,
				},
			},
			method:      "GET",
			url:         "http://example.com/test",
			expectError: false,
		},
		{
			name: "POST request with body",
			config: &EchoActionConfig{
				EchoConfig: EchoConfig{
					IncludeContext: false,
				},
			},
			method:      "POST",
			url:         "http://example.com/api/test",
			body:        `{"test":"data"}`,
			expectError: false,
		},
		{
			name: "request with headers",
			config: &EchoActionConfig{
				EchoConfig: EchoConfig{
					IncludeContext: false,
				},
			},
			method: "GET",
			url:    "http://example.com/test",
			headers: map[string]string{
				"X-Custom-Header": "value",
				"Authorization":   "Bearer token123",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transportFn := EchoTransportFn(tt.config)

			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = bytes.NewReader([]byte(tt.body))
			}

			req, err := http.NewRequest(tt.method, tt.url, bodyReader)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			resp, err := transportFn(req)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
			}

			if resp.Header.Get("Content-Type") != "application/json" {
				t.Errorf("expected content type application/json, got %s", resp.Header.Get("Content-Type"))
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}
			resp.Body.Close()

			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Verify timestamp exists
			if _, ok := result["timestamp"]; !ok {
				t.Error("expected timestamp in response")
			}

			// Verify request info exists
			requestInfo, ok := result["request"].(map[string]interface{})
			if !ok {
				t.Fatal("expected request info in response")
			}

			if requestInfo["method"] != tt.method {
				t.Errorf("expected method %s, got %v", tt.method, requestInfo["method"])
			}

			if requestInfo["url"] != tt.url {
				t.Errorf("expected url %s, got %v", tt.url, requestInfo["url"])
			}

			// If body was sent, verify it's in the response
			if tt.body != "" {
				if requestInfo["body"] != tt.body {
					t.Errorf("expected body %s, got %v", tt.body, requestInfo["body"])
				}
			}

			// Verify headers are included
			if _, ok := requestInfo["headers"]; !ok {
				t.Error("expected headers in response")
			}
		})
	}
}

