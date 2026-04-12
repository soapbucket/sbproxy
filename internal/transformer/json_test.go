package transformer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockStreamingConfigProvider implements StreamingConfigProvider for testing
type mockStreamingConfigProvider struct {
	config StreamingConfig
}

func (m *mockStreamingConfigProvider) GetStreamingConfig() StreamingConfig {
	return m.config
}

func TestOptimizeJSON_SizeCheck(t *testing.T) {
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled:            true,
			TransformThreshold: 1024, // 1KB
		},
	}

	tests := []struct {
		name            string
		jsonSize        int
		shouldTransform bool
		jsonData        string
	}{
		{
			name:            "Small JSON - should transform",
			jsonSize:        500,
			shouldTransform: true,
			jsonData:        `{"key":"value","nested":{"a":1,"b":2}}`,
		},
		{
			name:            "Large JSON - should skip",
			jsonSize:        2000,
			shouldTransform: false,
			jsonData:        strings.Repeat(`{"key":"value"},`, 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create JSON data
			jsonData := tt.jsonData
			if len(jsonData) < tt.jsonSize {
				// Pad with spaces to reach desired size
				jsonData = jsonData + strings.Repeat(" ", tt.jsonSize-len(jsonData))
			}

			resp := &http.Response{
				StatusCode:    http.StatusOK,
				ContentLength: int64(len(jsonData)),
				Body:          io.NopCloser(bytes.NewReader([]byte(jsonData))),
				Header:        make(http.Header),
			}
			resp.Header.Set("Content-Type", "application/json")

			req := &http.Request{}
			ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
			resp.Request = req.WithContext(ctx)

			opts := JSONOptions{
				RemoveEmptyObjects: true,
			}

			err := optimizeJSON(resp, opts)
			if err != nil {
				t.Fatalf("optimizeJSON error: %v", err)
			}

			resultBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll error: %v", err)
			}

			if tt.shouldTransform {
				// Should be transformed (optimized)
				// Check if it's valid JSON
				var testObj interface{}
				if err := json.Unmarshal(resultBody, &testObj); err != nil {
					t.Errorf("Result is not valid JSON: %v", err)
				}
				// Size might be different after optimization
			} else {
				// Should be original (passthrough)
				if len(resultBody) != len(jsonData) {
					t.Errorf("Expected original body size %d, got %d", len(jsonData), len(resultBody))
				}
			}
		})
	}
}

func TestOptimizeJSON_ThresholdDuringRead(t *testing.T) {
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled:            true,
			TransformThreshold: 1024, // 1KB
		},
	}

	// Create JSON larger than threshold but with unknown Content-Length
	jsonData := strings.Repeat(`{"key":"value"},`, 100)
	bodyData := []byte(jsonData)

	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: -1, // Unknown length
		Body:          io.NopCloser(bytes.NewReader(bodyData)),
		Header:        make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	req := &http.Request{}
	ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
	resp.Request = req.WithContext(ctx)

	opts := JSONOptions{
		RemoveEmptyObjects: true,
	}

	err := optimizeJSON(resp, opts)
	if err != nil {
		t.Fatalf("optimizeJSON error: %v", err)
	}

	// Should pass through without transformation
	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if len(resultBody) != len(bodyData) {
		t.Errorf("Expected original body size %d, got %d", len(bodyData), len(resultBody))
	}
}

func TestOptimizeJSON_NoConfig(t *testing.T) {
	// Test with no config - should use defaults
	jsonData := `{"key":"value","nested":{"a":1,"b":2}}`
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(jsonData)),
		Body:          io.NopCloser(bytes.NewReader([]byte(jsonData))),
		Header:        make(http.Header),
		Request:       &http.Request{}, // No config in context
	}
	resp.Header.Set("Content-Type", "application/json")

	opts := JSONOptions{
		RemoveEmptyObjects: true,
	}

	err := optimizeJSON(resp, opts)
	if err != nil {
		t.Fatalf("optimizeJSON error: %v", err)
	}

	// Should transform (default threshold is 10MB, so small JSON is fine)
	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	// Should be valid JSON
	var testObj interface{}
	if err := json.Unmarshal(resultBody, &testObj); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}
}

func TestOptimizeJSON_DisabledStreaming(t *testing.T) {
	// Test with streaming disabled - should always transform
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled: false,
		},
	}

	jsonData := strings.Repeat(`{"key":"value"},`, 100) // Large JSON
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(jsonData)),
		Body:          io.NopCloser(bytes.NewReader([]byte(jsonData))),
		Header:        make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	req := &http.Request{}
	ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
	resp.Request = req.WithContext(ctx)

	opts := JSONOptions{
		RemoveEmptyObjects: true,
	}

	err := optimizeJSON(resp, opts)
	if err != nil {
		t.Fatalf("optimizeJSON error: %v", err)
	}

	// Should transform even though JSON is large (streaming disabled)
	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	// Should be valid JSON
	var testObj interface{}
	if err := json.Unmarshal(resultBody, &testObj); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}
}

func TestOptimizeJSON_EmptyBody(t *testing.T) {
	resp := &http.Response{
		StatusCode:    http.StatusNoContent,
		ContentLength: 0,
		Body:          io.NopCloser(bytes.NewReader([]byte{})),
		Header:        make(http.Header),
	}

	opts := JSONOptions{
		RemoveEmptyObjects: true,
	}

	err := optimizeJSON(resp, opts)
	if err != nil {
		t.Fatalf("optimizeJSON error: %v", err)
	}

	// Empty body should remain empty
	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if len(resultBody) != 0 {
		t.Errorf("Expected empty body, got %d bytes", len(resultBody))
	}
}

func TestGetStreamingConfigProviderFromRequest_Transform(t *testing.T) {
	t.Run("With provider in context", func(t *testing.T) {
		provider := &mockStreamingConfigProvider{
			config: StreamingConfig{
				Enabled:            true,
				TransformThreshold: 1024,
			},
		}
		req := &http.Request{}
		ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
		req = req.WithContext(ctx)

		result := getStreamingConfigProviderFromRequest(req)
		if result == nil {
			t.Fatal("Expected provider, got nil")
		}
		config := result.GetStreamingConfig()
		if !config.Enabled {
			t.Error("Expected streaming enabled, got disabled")
		}
		if config.TransformThreshold != 1024 {
			t.Errorf("Expected transform threshold 1024, got %d", config.TransformThreshold)
		}
	})

	t.Run("Without provider in context", func(t *testing.T) {
		req := &http.Request{}
		result := getStreamingConfigProviderFromRequest(req)
		if result != nil {
			t.Error("Expected nil, got provider")
		}
	})

	t.Run("Nil request", func(t *testing.T) {
		result := getStreamingConfigProviderFromRequest(nil)
		if result != nil {
			t.Error("Expected nil, got provider")
		}
	})
}

func TestApplyRules_JSONPathSyntax(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		rules    []JSONRule
		expected string
	}{
		{
			name:  "JSONPath with $ prefix - set root field",
			input: `{"user_id": 123, "first_name": "John"}`,
			rules: []JSONRule{
				{Path: "$.id", Value: 123},
				{Path: "$.apiVersion", Value: "2.0"},
			},
			expected: `{"user_id":123,"first_name":"John","id":123,"apiVersion":"2.0"}`,
		},
		{
			name:  "JSONPath with $ prefix - nested object",
			input: `{"first_name": "John", "last_name": "Doe"}`,
			rules: []JSONRule{
				{Path: "$.name", Value: map[string]interface{}{"first": "John", "last": "Doe"}},
			},
			expected: `{"first_name":"John","last_name":"Doe","name":{"first":"John","last":"Doe"}}`,
		},
		{
			name:  "JSONPath with $ prefix - remove field with null",
			input: `{"user_id": 123, "first_name": "John", "internal": "secret"}`,
			rules: []JSONRule{
				{Path: "$.internal", Value: nil},
			},
			expected: `{"user_id":123,"first_name":"John","internal":null}`,
		},
		{
			name:  "Path without $ prefix - should still work",
			input: `{"user_id": 123}`,
			rules: []JSONRule{
				{Path: "id", Value: 456},
			},
			expected: `{"user_id":123,"id":456}`,
		},
		{
			name:  "JSONPath with @ prefix - set root field",
			input: `{"user_id": 123}`,
			rules: []JSONRule{
				{Path: "@.id", Value: 456},
			},
			expected: `{"user_id":123,"id":456}`,
		},
		{
			name:  "V1 to V2 migration transformation",
			input: `{"user_id":123,"first_name":"John","last_name":"Doe","email_address":"john@example.com"}`,
			rules: []JSONRule{
				{Path: "$.apiVersion", Value: "2.0"},
				{Path: "$.id", Value: 123},
				{Path: "$.name", Value: map[string]interface{}{"first": "John", "last": "Doe"}},
				{Path: "$.email", Value: "john@example.com"},
				{Path: "$.user_id", Value: nil},
				{Path: "$.first_name", Value: nil},
				{Path: "$.last_name", Value: nil},
				{Path: "$.email_address", Value: nil},
			},
			expected: `{"user_id":null,"first_name":null,"last_name":null,"email_address":null,"apiVersion":"2.0","id":123,"name":{"first":"John","last":"Doe"},"email":"john@example.com"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data interface{}
			if err := json.Unmarshal([]byte(tt.input), &data); err != nil {
				t.Fatalf("failed to unmarshal input: %v", err)
			}

			if err := applyRules(data, tt.rules); err != nil {
				t.Fatalf("applyRules failed: %v", err)
			}

			result, err := json.Marshal(data)
			if err != nil {
				t.Fatalf("failed to marshal result: %v", err)
			}

			// Compare JSON objects rather than strings
			var expectedObj, resultObj interface{}
			if err := json.Unmarshal([]byte(tt.expected), &expectedObj); err != nil {
				t.Fatalf("failed to unmarshal expected: %v", err)
			}
			if err := json.Unmarshal(result, &resultObj); err != nil {
				t.Fatalf("failed to unmarshal result: %v", err)
			}

			expectedBytes, _ := json.Marshal(expectedObj)
			resultBytes, _ := json.Marshal(resultObj)

			if string(expectedBytes) != string(resultBytes) {
				t.Errorf("Result mismatch:\nexpected: %s\ngot:      %s", expectedBytes, resultBytes)
			}
		})
	}
}

func TestOptimizeJSON_V1ToV2Migration(t *testing.T) {
	// This test simulates the v2-transformer demo migration
	input := `{"user_id":123,"first_name":"John","last_name":"Doe","email_address":"john@example.com","created_at":"2024-01-15T10:30:00Z","is_active":true,"account_type":"premium","internal_id":"INT-12345"}`

	opts := JSONOptions{
		RemoveEmptyStrings: true,
		PrettyPrint:        false,
		Rules: []JSONRule{
			{Path: "$.apiVersion", Value: "2.0"},
			{Path: "$.id", Value: 123},
			{Path: "$.name", Value: map[string]interface{}{"first": "John", "last": "Doe"}},
			{Path: "$.email", Value: "john@example.com"},
			{Path: "$.metadata", Value: map[string]interface{}{
				"createdAt": "2024-01-15T10:30:00Z",
				"status":    "active",
				"tier":      "premium",
			}},
			{Path: "$.user_id", Value: nil},
			{Path: "$.first_name", Value: nil},
			{Path: "$.last_name", Value: nil},
			{Path: "$.email_address", Value: nil},
			{Path: "$.created_at", Value: nil},
			{Path: "$.is_active", Value: nil},
			{Path: "$.account_type", Value: nil},
			{Path: "$.internal_id", Value: "[REDACTED]"},
		},
	}

	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(input)),
		Body:          io.NopCloser(bytes.NewReader([]byte(input))),
		Header:        make(http.Header),
		Request:       &http.Request{},
	}
	resp.Header.Set("Content-Type", "application/json")

	err := optimizeJSON(resp, opts)
	if err != nil {
		t.Fatalf("optimizeJSON error: %v", err)
	}

	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	// Parse the result
	var result map[string]interface{}
	if err := json.Unmarshal(resultBody, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// Verify expected fields exist at root level (not under "$")
	if _, exists := result["$"]; exists {
		t.Errorf("Result should NOT have a '$' key - JSONPath prefix should be normalized")
	}

	if result["apiVersion"] != "2.0" {
		t.Errorf("Expected apiVersion '2.0', got: %v", result["apiVersion"])
	}

	if result["email"] != "john@example.com" {
		t.Errorf("Expected email 'john@example.com', got: %v", result["email"])
	}

	if result["internal_id"] != "[REDACTED]" {
		t.Errorf("Expected internal_id '[REDACTED]', got: %v", result["internal_id"])
	}

	// Verify nested name object
	name, ok := result["name"].(map[string]interface{})
	if !ok {
		t.Errorf("Expected name to be an object, got: %T", result["name"])
	} else {
		if name["first"] != "John" {
			t.Errorf("Expected name.first 'John', got: %v", name["first"])
		}
		if name["last"] != "Doe" {
			t.Errorf("Expected name.last 'Doe', got: %v", name["last"])
		}
	}

	// Verify old fields are removed (set to null, then pruned if applicable)
	// Note: prune removes nil values, so these fields should not exist
	for _, field := range []string{"user_id", "first_name", "last_name", "email_address", "created_at", "is_active", "account_type"} {
		if _, exists := result[field]; exists {
			t.Errorf("Field %q should have been removed (set to null)", field)
		}
	}
}
