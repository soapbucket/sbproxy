package reqctx

import (
	"testing"
)

func TestOriginalRequestData_BodyAsJSON(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		isJSON   bool
		wantType string // "object", "array", "string", "number", "bool", "nil"
	}{
		{
			name:     "JSON object",
			body:     []byte(`{"name": "John", "age": 30}`),
			isJSON:   true,
			wantType: "object",
		},
		{
			name:     "JSON array",
			body:     []byte(`[1, 2, 3, 4, 5]`),
			isJSON:   true,
			wantType: "array",
		},
		{
			name:     "JSON string primitive",
			body:     []byte(`"hello world"`),
			isJSON:   true,
			wantType: "string",
		},
		{
			name:     "JSON number primitive",
			body:     []byte(`42`),
			isJSON:   true,
			wantType: "number",
		},
		{
			name:     "JSON boolean primitive",
			body:     []byte(`true`),
			isJSON:   true,
			wantType: "bool",
		},
		{
			name:     "JSON null",
			body:     []byte(`null`),
			isJSON:   true,
			wantType: "nil",
		},
		{
			name:     "Invalid JSON",
			body:     []byte(`{invalid json`),
			isJSON:   true,
			wantType: "nil",
		},
		{
			name:     "Empty body",
			body:     []byte{},
			isJSON:   true,
			wantType: "nil",
		},
		{
			name:     "Non-JSON content",
			body:     []byte(`plain text`),
			isJSON:   false,
			wantType: "nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := &OriginalRequestData{
				Method:      "POST",
				URL:         "http://example.com/api",
				Body:        tt.body,
				IsJSON:      tt.isJSON,
				ContentType: "application/json",
			}

			result := orig.BodyAsJSON()

			// Check type
			switch tt.wantType {
			case "object":
				if _, ok := result.(map[string]any); !ok {
					t.Errorf("BodyAsJSON() should return map[string]any for JSON object, got %T", result)
				}
			case "array":
				if _, ok := result.([]any); !ok {
					t.Errorf("BodyAsJSON() should return []any for JSON array, got %T", result)
				}
			case "string":
				if _, ok := result.(string); !ok {
					t.Errorf("BodyAsJSON() should return string for JSON string, got %T", result)
				}
			case "number":
				// JSON numbers can be float64
				if _, ok := result.(float64); !ok {
					t.Errorf("BodyAsJSON() should return float64 for JSON number, got %T", result)
				}
			case "bool":
				if _, ok := result.(bool); !ok {
					t.Errorf("BodyAsJSON() should return bool for JSON boolean, got %T", result)
				}
			case "nil":
				if result != nil {
					t.Errorf("BodyAsJSON() should return nil, got %v", result)
				}
			}
		})
	}
}

func TestOriginalRequestData_BodyAsJSON_ObjectAccess(t *testing.T) {
	orig := &OriginalRequestData{
		Body:   []byte(`{"name": "John", "age": 30, "active": true}`),
		IsJSON: true,
	}

	result := orig.BodyAsJSON()
	obj, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("Expected map[string]any, got %T", result)
	}

	if obj["name"] != "John" {
		t.Errorf("Expected name to be 'John', got %v", obj["name"])
	}

	if obj["age"].(float64) != 30 {
		t.Errorf("Expected age to be 30, got %v", obj["age"])
	}

	if obj["active"] != true {
		t.Errorf("Expected active to be true, got %v", obj["active"])
	}
}

func TestOriginalRequestData_BodyAsJSON_ArrayAccess(t *testing.T) {
	orig := &OriginalRequestData{
		Body:   []byte(`["apple", "banana", "cherry"]`),
		IsJSON: true,
	}

	result := orig.BodyAsJSON()
	arr, ok := result.([]any)
	if !ok {
		t.Fatalf("Expected []any, got %T", result)
	}

	if len(arr) != 3 {
		t.Errorf("Expected array length 3, got %d", len(arr))
	}

	if arr[0] != "apple" {
		t.Errorf("Expected first element to be 'apple', got %v", arr[0])
	}
}

func TestOriginalRequestData_BodyAsJSON_NilReceiver(t *testing.T) {
	var orig *OriginalRequestData
	result := orig.BodyAsJSON()
	if result != nil {
		t.Errorf("Expected nil for nil receiver, got %v", result)
	}
}

// Benchmark to verify performance of on-demand parsing
func BenchmarkOriginalRequestData_BodyAsJSON(b *testing.B) {
	b.ReportAllocs()
	orig := &OriginalRequestData{
		Body:   []byte(`{"name": "John", "age": 30, "email": "john@example.com", "active": true}`),
		IsJSON: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = orig.BodyAsJSON()
	}
}

