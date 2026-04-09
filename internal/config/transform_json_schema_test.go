package config

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestJSONSchemaTransform_Valid(t *testing.T) {
	configJSON := `{
		"type": "json_schema",
		"action": "validate",
		"schema": {
			"type": "object",
			"required": ["name", "age"],
			"properties": {
				"name": {"type": "string"},
				"age": {"type": "integer"}
			}
		}
	}`

	tc, err := NewJSONSchemaTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	// Valid response body
	body := `{"name":"John","age":30}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("valid response should keep 200, got %d", resp.StatusCode)
	}
}

func TestJSONSchemaTransform_InvalidReject(t *testing.T) {
	configJSON := `{
		"type": "json_schema",
		"action": "validate",
		"schema": {
			"type": "object",
			"required": ["name"],
			"properties": {
				"name": {"type": "string"}
			}
		}
	}`

	tc, err := NewJSONSchemaTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	// Missing required field "name"
	body := `{"age":30}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("invalid response should be 502, got %d", resp.StatusCode)
	}
}

func TestJSONSchemaTransform_WarnMode(t *testing.T) {
	configJSON := `{
		"type": "json_schema",
		"action": "warn",
		"schema": {
			"type": "object",
			"required": ["name"],
			"properties": {
				"name": {"type": "string"}
			}
		}
	}`

	tc, err := NewJSONSchemaTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"age":30}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("warn mode should keep 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("X-Schema-Valid") != "false" {
		t.Error("expected X-Schema-Valid: false header")
	}
}

func TestJSONSchemaTransform_EmptyBody(t *testing.T) {
	configJSON := `{
		"type": "json_schema",
		"action": "validate",
		"schema": {"type": "object"}
	}`

	tc, err := NewJSONSchemaTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	resp := &http.Response{
		StatusCode: 204,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 204 {
		t.Errorf("empty body should keep status, got %d", resp.StatusCode)
	}
}

func TestJSONSchemaTransform_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"no schema", `{"type":"json_schema","action":"validate"}`},
		{"invalid action", `{"type":"json_schema","action":"bad","schema":{"type":"object"}}`},
		{"bad json", `{"type":"json_schema",`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJSONSchemaTransform([]byte(tt.json))
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}
