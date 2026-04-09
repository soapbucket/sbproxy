package config

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestJSONProjectionTransform_Include(t *testing.T) {
	configJSON := `{
		"type": "json_projection",
		"include": ["name", "email"]
	}`

	tc, err := NewJSONProjectionTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"name":"John","email":"j@test.com","age":30,"internal_id":"abc"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	resultStr := string(result)

	if !bytes.Contains(result, []byte(`"name"`)) {
		t.Error("included field 'name' should be present")
	}
	if !bytes.Contains(result, []byte(`"email"`)) {
		t.Error("included field 'email' should be present")
	}
	if bytes.Contains(result, []byte(`"age"`)) {
		t.Errorf("excluded field 'age' should not be present in: %s", resultStr)
	}
	if bytes.Contains(result, []byte(`"internal_id"`)) {
		t.Errorf("excluded field 'internal_id' should not be present in: %s", resultStr)
	}
}

func TestJSONProjectionTransform_Exclude(t *testing.T) {
	configJSON := `{
		"type": "json_projection",
		"exclude": ["internal_id", "debug"]
	}`

	tc, err := NewJSONProjectionTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"name":"John","internal_id":"abc","debug":true,"age":30}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)

	if bytes.Contains(result, []byte(`"internal_id"`)) {
		t.Error("excluded field should be removed")
	}
	if bytes.Contains(result, []byte(`"debug"`)) {
		t.Error("excluded field should be removed")
	}
	if !bytes.Contains(result, []byte(`"name"`)) {
		t.Error("non-excluded field should be preserved")
	}
}

func TestJSONProjectionTransform_NestedInclude(t *testing.T) {
	configJSON := `{
		"type": "json_projection",
		"include": ["user.name", "user.email"]
	}`

	tc, err := NewJSONProjectionTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"user":{"name":"John","email":"j@test.com","ssn":"123-45-6789"}}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)

	if bytes.Contains(result, []byte(`"ssn"`)) {
		t.Errorf("ssn should be excluded in: %s", string(result))
	}
	if !bytes.Contains(result, []byte(`"name"`)) {
		t.Error("name should be included")
	}
}

func TestJSONProjectionTransform_Flatten(t *testing.T) {
	configJSON := `{
		"type": "json_projection",
		"include": ["user.name", "user.email"],
		"flatten": true
	}`

	tc, err := NewJSONProjectionTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"user":{"name":"John","email":"j@test.com"}}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)

	// Flattened: {"name":"John","email":"j@test.com"} (no nested "user")
	if bytes.Contains(result, []byte(`"user"`)) {
		t.Errorf("flattened output should not have 'user' key: %s", string(result))
	}
	if !bytes.Contains(result, []byte(`"name"`)) {
		t.Error("flattened output should have 'name' at top level")
	}
}

func TestJSONProjectionTransform_EmptyBody(t *testing.T) {
	configJSON := `{
		"type": "json_projection",
		"include": ["name"]
	}`

	tc, err := NewJSONProjectionTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJSONProjectionTransform_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"no fields", `{"type":"json_projection"}`},
		{"bad json", `{"type":"json_projection",`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJSONProjectionTransform([]byte(tt.json))
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}
