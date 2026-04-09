package config

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestLoadMockConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name: "basic mock config",
			input: `{
				"type": "mock",
				"status_code": 200,
				"body": "hello world"
			}`,
			expectError: false,
		},
		{
			name: "mock with headers",
			input: `{
				"type": "mock",
				"status_code": 201,
				"headers": {"Content-Type": "application/json"},
				"body": "{\"ok\":true}"
			}`,
			expectError: false,
		},
		{
			name: "mock defaults to 200",
			input: `{
				"type": "mock"
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{bad json}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadMockConfig([]byte(tt.input))
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg == nil {
				t.Fatal("expected config but got nil")
			}
			if cfg.GetType() != TypeMock {
				t.Errorf("expected type %s, got %s", TypeMock, cfg.GetType())
			}
			if cfg.Transport() == nil {
				t.Error("expected transport to be set")
			}
		})
	}
}

func TestMockTransport_BasicResponse(t *testing.T) {
	cfg := &MockActionConfig{
		MockConfig: MockConfig{
			StatusCode: http.StatusTeapot,
			Headers:    map[string]string{"X-Custom": "value"},
			Body:       "I'm a teapot",
		},
	}

	transportFn := MockTransportFn(cfg)
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)

	resp, err := transportFn(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, resp.StatusCode)
	}

	if resp.Header.Get("X-Custom") != "value" {
		t.Errorf("expected X-Custom header, got %q", resp.Header.Get("X-Custom"))
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "I'm a teapot" {
		t.Errorf("expected body %q, got %q", "I'm a teapot", string(body))
	}
}

func TestMockTransport_DefaultStatusCode(t *testing.T) {
	input := `{"type": "mock"}`
	cfg, err := LoadMockConfig([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transportFn := cfg.Transport()
	req, _ := http.NewRequest("GET", "http://example.com/", nil)

	resp, err := transportFn(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestMockTransport_JSONBody(t *testing.T) {
	input := `{
		"type": "mock",
		"status_code": 200,
		"headers": {"Content-Type": "application/json"},
		"body": "{\"message\":\"hello\"}"
	}`
	cfg, err := LoadMockConfig([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transportFn := cfg.Transport()
	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	resp, err := transportFn(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json, got %s", resp.Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if result["message"] != "hello" {
		t.Errorf("expected message=hello, got %v", result["message"])
	}
}

func TestMockTransport_Delay(t *testing.T) {
	cfg := &MockActionConfig{
		MockConfig: MockConfig{
			StatusCode: 200,
		},
	}
	cfg.Delay.Duration = 100 * time.Millisecond

	transportFn := MockTransportFn(cfg)
	req, _ := http.NewRequest("GET", "http://example.com/", nil)

	start := time.Now()
	resp, err := transportFn(req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	if elapsed < 80*time.Millisecond {
		t.Errorf("expected delay of ~100ms, got %v", elapsed)
	}
}

func TestMockTransport_EmptyBody(t *testing.T) {
	cfg := &MockActionConfig{
		MockConfig: MockConfig{
			StatusCode: http.StatusNoContent,
		},
	}

	transportFn := MockTransportFn(cfg)
	req, _ := http.NewRequest("DELETE", "http://example.com/resource/1", nil)

	resp, err := transportFn(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if len(body) != 0 {
		t.Errorf("expected empty body, got %q", string(body))
	}
}
