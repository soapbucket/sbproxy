package config

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClassifyTransform_RegexMatch(t *testing.T) {
	configJSON := `{
		"type": "classify",
		"rules": [
			{"name": "contains_error", "pattern": "error|exception|failure"},
			{"name": "contains_user", "pattern": "\"user\""}
		]
	}`

	tc, err := NewClassifyTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"error":"something failed","user":"john"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	classification := resp.Header.Get("X-Content-Class")
	if classification == "" {
		t.Fatal("expected X-Content-Class header")
	}

	if !strings.Contains(classification, "contains_error") {
		t.Errorf("should match contains_error, got %s", classification)
	}
	if !strings.Contains(classification, "contains_user") {
		t.Errorf("should match contains_user, got %s", classification)
	}
}

func TestClassifyTransform_JSONPathMatch(t *testing.T) {
	configJSON := `{
		"type": "classify",
		"rules": [
			{"name": "has_email", "json_path": "user.email"},
			{"name": "has_admin", "json_path": "user.admin"}
		]
	}`

	tc, err := NewClassifyTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"user":{"email":"test@example.com","admin":false}}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	classification := resp.Header.Get("X-Content-Class")

	if !strings.Contains(classification, "has_email") {
		t.Errorf("should match has_email, got %q", classification)
	}
	// admin=false should NOT match (falsy value)
	if strings.Contains(classification, "has_admin") {
		t.Errorf("should not match has_admin (value is false), got %q", classification)
	}
}

func TestClassifyTransform_NoMatch(t *testing.T) {
	configJSON := `{
		"type": "classify",
		"rules": [
			{"name": "has_secret", "pattern": "secret_key"}
		]
	}`

	tc, err := NewClassifyTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"name":"John"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Header.Get("X-Content-Class") != "" {
		t.Error("no match should not set classification header")
	}
}

func TestClassifyTransform_CustomHeaderName(t *testing.T) {
	configJSON := `{
		"type": "classify",
		"header_name": "X-Data-Type",
		"rules": [
			{"name": "json_data", "pattern": "\\{"}
		]
	}`

	tc, err := NewClassifyTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"data":"test"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Header.Get("X-Data-Type") == "" {
		t.Error("expected custom header X-Data-Type to be set")
	}
}

func TestClassifyTransform_BodyUnmodified(t *testing.T) {
	configJSON := `{
		"type": "classify",
		"rules": [
			{"name": "any", "pattern": "."}
		]
	}`

	tc, err := NewClassifyTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"original":"data"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	if string(result) != body {
		t.Errorf("body should be unmodified, got %s", string(result))
	}
}

func TestClassifyTransform_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"no rules", `{"type":"classify","rules":[]}`},
		{"invalid regex", `{"type":"classify","rules":[{"name":"bad","pattern":"[invalid"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClassifyTransform([]byte(tt.json))
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}
