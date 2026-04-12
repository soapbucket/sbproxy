package callback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCallback_HandleJSONObject tests callback with JSON object response
func TestCallback_HandleJSONObject(t *testing.T) {
	// Create test server that returns JSON object
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"name":  "John",
			"email": "john@example.com",
			"age":   30,
		})
	}))
	defer server.Close()

	callback := &Callback{
		URL:          server.URL + "/users",
		Method:       "POST",
		VariableName: "user", // Explicit name
	}

	ctx := context.Background()
	result, err := callback.Do(ctx, nil)
	if err != nil {
		t.Fatalf("Callback failed: %v", err)
	}

	// Result is wrapped in variable_name
	userData, ok := result["user"].(map[string]any)
	if !ok {
		t.Fatalf("Expected result['user'] to be map, got %T", result["user"])
	}

	if userData["name"] != "John" {
		t.Errorf("Expected name to be 'John', got %v", userData["name"])
	}
	if userData["email"] != "john@example.com" {
		t.Errorf("Expected email to be 'john@example.com', got %v", userData["email"])
	}
	if userData["age"].(float64) != 30 {
		t.Errorf("Expected age to be 30, got %v", userData["age"])
	}
}

// TestCallback_HandleJSONArray tests callback with JSON array response
func TestCallback_HandleJSONArray(t *testing.T) {
	// Create test server that returns JSON array
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"apple", "banana", "cherry"})
	}))
	defer server.Close()

	callback := &Callback{
		URL:          server.URL + "/fruits",
		Method:       "GET",
		VariableName: "fruits", // Explicit name
	}

	ctx := context.Background()
	result, err := callback.Do(ctx, nil)
	if err != nil {
		t.Fatalf("Callback failed: %v", err)
	}

	// Result is wrapped in variable_name
	fruitsData, ok := result["fruits"].(map[string]any)
	if !ok {
		t.Fatalf("Expected result['fruits'] to be map, got %T", result["fruits"])
	}

	// For arrays, the array itself is in "data" field
	data, ok := fruitsData["data"].([]any)
	if !ok {
		t.Fatalf("Expected fruits['data'] to be []any, got %T", fruitsData["data"])
	}

	if len(data) != 3 {
		t.Errorf("Expected array length 3, got %d", len(data))
	}
	if data[0] != "apple" {
		t.Errorf("Expected first element to be 'apple', got %v", data[0])
	}
}

// TestCallback_HandleJSONPrimitive tests callback with JSON primitive responses
func TestCallback_HandleJSONPrimitive(t *testing.T) {
	tests := []struct {
		name     string
		response any
		wantType string
	}{
		{
			name:     "String primitive",
			response: "hello world",
			wantType: "string",
		},
		{
			name:     "Number primitive",
			response: 42,
			wantType: "number",
		},
		{
			name:     "Boolean primitive",
			response: true,
			wantType: "bool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			callback := &Callback{
				URL:          server.URL + "/value",
				Method:       "GET",
				VariableName: "val", // Explicit name
			}

			ctx := context.Background()
			result, err := callback.Do(ctx, nil)
			if err != nil {
				t.Fatalf("Callback failed: %v", err)
			}

			// Result is wrapped in variable_name
			valData, ok := result["val"].(map[string]any)
			if !ok {
				t.Fatalf("Expected result['val'] to be map, got %T", result["val"])
			}

			// For primitives, the value is in "data" field
			data := valData["data"]
			if data == nil {
				t.Fatalf("Expected val['data'] to exist, got nil")
			}

			// Verify type
			switch tt.wantType {
			case "string":
				if _, ok := data.(string); !ok {
					t.Errorf("Expected data to be string, got %T", data)
				}
			case "number":
				if _, ok := data.(float64); !ok {
					t.Errorf("Expected data to be float64, got %T", data)
				}
			case "bool":
				if _, ok := data.(bool); !ok {
					t.Errorf("Expected data to be bool, got %T", data)
				}
			}
		})
	}
}

// TestCallback_WithVariableName tests variable name wrapping with different JSON types
func TestCallback_WithVariableName(t *testing.T) {
	tests := []struct {
		name         string
		response     any
		variableName string
		checkAccess  func(t *testing.T, result map[string]any)
	}{
		{
			name:         "Object with variable name",
			response:     map[string]any{"user": "john"},
			variableName: "user_data",
			checkAccess: func(t *testing.T, result map[string]any) {
				userData, ok := result["user_data"].(map[string]any)
				if !ok {
					t.Fatalf("Expected user_data to be map, got %T", result["user_data"])
				}
				if userData["user"] != "john" {
					t.Errorf("Expected user to be 'john', got %v", userData["user"])
				}
			},
		},
		{
			name:         "Array with variable name",
			response:     []string{"a", "b", "c"},
			variableName: "items",
			checkAccess: func(t *testing.T, result map[string]any) {
				items, ok := result["items"].(map[string]any)
				if !ok {
					t.Fatalf("Expected items to be map, got %T", result["items"])
				}
				data, ok := items["data"].([]any)
				if !ok {
					t.Fatalf("Expected items.data to be []any, got %T", items["data"])
				}
				if len(data) != 3 {
					t.Errorf("Expected 3 items, got %d", len(data))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			callback := &Callback{
				URL:          server.URL,
				Method:       "GET",
				VariableName: tt.variableName,
			}

			ctx := context.Background()
			result, err := callback.Do(ctx, nil)
			if err != nil {
				t.Fatalf("Callback failed: %v", err)
			}

			tt.checkAccess(t, result)
		})
	}
}

// TestCallback_MultipleCallbacksWithDifferentTypes tests merging results from different JSON types
func TestCallback_MultipleCallbacksWithDifferentTypes(t *testing.T) {
	// Server 1: Returns object
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"email": "user@example.com"})
	}))
	defer server1.Close()

	// Server 2: Returns array
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{"tag1", "tag2"})
	}))
	defer server2.Close()

	callbacks := Callbacks{
		{
			URL:          server1.URL,
			Method:       "GET",
			VariableName: "email_data",
		},
		{
			URL:          server2.URL,
			Method:       "GET",
			VariableName: "tags",
		},
	}

	ctx := context.Background()
	result, err := callbacks.DoSequential(ctx, nil)
	if err != nil {
		t.Fatalf("Callbacks failed: %v", err)
	}

	// Check email_data (object)
	emailData, ok := result["email_data"].(map[string]any)
	if !ok {
		t.Fatalf("Expected email_data to be map, got %T", result["email_data"])
	}
	if emailData["email"] != "user@example.com" {
		t.Errorf("Expected email, got %v", emailData["email"])
	}

	// Check tags (array wrapped in data)
	tags, ok := result["tags"].(map[string]any)
	if !ok {
		t.Fatalf("Expected tags to be map, got %T", result["tags"])
	}
	tagsData, ok := tags["data"].([]any)
	if !ok {
		t.Fatalf("Expected tags.data to be []any, got %T", tags["data"])
	}
	if len(tagsData) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(tagsData))
	}
}

// Benchmark callback with different JSON types
func BenchmarkCallback_JSONObject(b *testing.B) {
	b.ReportAllocs()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"name": "John", "age": 30})
	}))
	defer server.Close()

	callback := &Callback{
		URL:    server.URL,
		Method: "GET",
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = callback.Do(ctx, nil)
	}
}

func BenchmarkCallback_JSONArray(b *testing.B) {
	b.ReportAllocs()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]int{1, 2, 3, 4, 5})
	}))
	defer server.Close()

	callback := &Callback{
		URL:    server.URL,
		Method: "GET",
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = callback.Do(ctx, nil)
	}
}
