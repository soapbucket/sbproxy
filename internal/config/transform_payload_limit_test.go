package config

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPayloadLimitTransform_UnderLimit(t *testing.T) {
	configJSON := `{
		"type": "payload_limit",
		"max_size": 1024,
		"action": "reject"
	}`

	tc, err := NewPayloadLimitTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"name":"John"}`
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(body))),
		ContentLength: int64(len(body)),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("under-limit response should keep 200, got %d", resp.StatusCode)
	}
}

func TestPayloadLimitTransform_Reject(t *testing.T) {
	configJSON := `{
		"type": "payload_limit",
		"max_size": 10,
		"action": "reject"
	}`

	tc, err := NewPayloadLimitTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := strings.Repeat("x", 100)
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(body))),
		ContentLength: int64(len(body)),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 413 {
		t.Errorf("over-limit response should be 413, got %d", resp.StatusCode)
	}
}

func TestPayloadLimitTransform_Truncate(t *testing.T) {
	configJSON := `{
		"type": "payload_limit",
		"max_size": 10,
		"action": "truncate"
	}`

	tc, err := NewPayloadLimitTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := strings.Repeat("abcdef", 10) // 60 bytes
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(body))),
		ContentLength: int64(len(body)),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	if len(result) != 10 {
		t.Errorf("truncated body should be 10 bytes, got %d", len(result))
	}

	if resp.Header.Get("X-Payload-Truncated") != "true" {
		t.Error("expected X-Payload-Truncated header")
	}
}

func TestPayloadLimitTransform_Warn(t *testing.T) {
	configJSON := `{
		"type": "payload_limit",
		"max_size": 10,
		"action": "warn"
	}`

	tc, err := NewPayloadLimitTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := strings.Repeat("x", 100)
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(body))),
		ContentLength: int64(len(body)),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("warn mode should keep 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("X-Payload-Warning") == "" {
		t.Error("expected X-Payload-Warning header")
	}
}

func TestPayloadLimitTransform_UnknownContentLength(t *testing.T) {
	configJSON := `{
		"type": "payload_limit",
		"max_size": 10,
		"action": "reject"
	}`

	tc, err := NewPayloadLimitTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := strings.Repeat("x", 100)
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(bytes.NewReader([]byte(body))),
		ContentLength: -1, // Unknown
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 413 {
		t.Errorf("over-limit response should be 413, got %d", resp.StatusCode)
	}
}

func TestPayloadLimitTransform_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"zero max_size", `{"type":"payload_limit","max_size":0}`},
		{"negative max_size", `{"type":"payload_limit","max_size":-1}`},
		{"invalid action", `{"type":"payload_limit","max_size":100,"action":"bad"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPayloadLimitTransform([]byte(tt.json))
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}
