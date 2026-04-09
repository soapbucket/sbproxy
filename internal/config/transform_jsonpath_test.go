package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Helper function to compare JSON equality
func assertJSONEqual(t *testing.T, expected, actual string) {
	t.Helper()
	var expectedJSON, actualJSON interface{}
	
	if err := json.Unmarshal([]byte(expected), &expectedJSON); err != nil {
		t.Fatalf("failed to unmarshal expected JSON: %v", err)
	}
	
	if err := json.Unmarshal([]byte(actual), &actualJSON); err != nil {
		t.Fatalf("failed to unmarshal actual JSON: %v", err)
	}
	
	if !reflect.DeepEqual(expectedJSON, actualJSON) {
		t.Errorf("JSON not equal:\nexpected: %s\nactual:   %s", expected, actual)
	}
}

func TestJSONPathTransform_Set(t *testing.T) {
	input := []byte(`{"user": {"name": "John", "age": 30}}`)
	
	transform := NewJSONPathTransform([]JSONPathOperation{
		{
			Type:  JSONPathSet,
			Path:  "user.age",
			Value: 31,
		},
	})

	output, err := transform.Transform(input)
	if err != nil {
		t.Fatalf("transform failed: %v", err)
	}

	expected := `{"user":{"name":"John","age":31}}`
	assertJSONEqual(t, expected, string(output))
}

func TestJSONPathTransform_Delete(t *testing.T) {
	input := []byte(`{"user": {"name": "John", "age": 30, "internal": "secret"}}`)
	
	transform := NewJSONPathTransform([]JSONPathOperation{
		{
			Type: JSONPathDelete,
			Path: "user.internal",
		},
	})

	output, err := transform.Transform(input)
	if err != nil {
		t.Fatalf("transform failed: %v", err)
	}

	expected := `{"user":{"name":"John","age":30}}`
	assertJSONEqual(t, expected, string(output))
}

func TestJSONPathTransform_Copy(t *testing.T) {
	input := []byte(`{"user": {"email": "john@example.com"}}`)
	
	transform := NewJSONPathTransform([]JSONPathOperation{
		{
			Type:   JSONPathCopy,
			Path:   "user.email",
			Target: "contact.email",
		},
	})

	output, err := transform.Transform(input)
	if err != nil {
		t.Fatalf("transform failed: %v", err)
	}

	expected := `{"user":{"email":"john@example.com"},"contact":{"email":"john@example.com"}}`
	assertJSONEqual(t, expected, string(output))
}

func TestJSONPathTransform_Extract(t *testing.T) {
	input := []byte(`{"user": {"email": "john@example.com", "name": "John"}}`)
	
	transform := NewJSONPathTransform([]JSONPathOperation{
		{
			Type:   JSONPathExtract,
			Path:   "user.email",
			Target: "X-User-Email",
		},
		{
			Type:   JSONPathExtract,
			Path:   "user.name",
			Target: "X-User-Name",
		},
	})

	headers := transform.ExtractToHeaders(input)

	if headers["X-User-Email"] != "john@example.com" {
		t.Errorf("expected email header, got: %v", headers)
	}

	if headers["X-User-Name"] != "John" {
		t.Errorf("expected name header, got: %v", headers)
	}
}

func TestJSONPathTransform_MultipleOperations(t *testing.T) {
	input := []byte(`{"user": {"name": "John", "age": 30, "internal": "secret"}}`)
	
	transform := NewJSONPathTransform([]JSONPathOperation{
		{
			Type:  JSONPathSet,
			Path:  "user.age",
			Value: 31,
		},
		{
			Type: JSONPathDelete,
			Path: "user.internal",
		},
		{
			Type:  JSONPathSet,
			Path:  "user.verified",
			Value: true,
		},
	})

	output, err := transform.Transform(input)
	if err != nil {
		t.Fatalf("transform failed: %v", err)
	}

	expected := `{"user":{"name":"John","age":31,"verified":true}}`
	assertJSONEqual(t, expected, string(output))
}

func TestJSONPathTransform_InvalidJSON(t *testing.T) {
	input := []byte(`not valid json`)
	
	transform := NewJSONPathTransform([]JSONPathOperation{
		{
			Type:  JSONPathSet,
			Path:  "field",
			Value: "value",
		},
	})

	_, err := transform.Transform(input)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestJSONPathTransform_NestedPaths(t *testing.T) {
	input := []byte(`{"a": {"b": {"c": {"d": "value"}}}}`)
	
	transform := NewJSONPathTransform([]JSONPathOperation{
		{
			Type:  JSONPathSet,
			Path:  "a.b.c.d",
			Value: "new_value",
		},
	})

	output, err := transform.Transform(input)
	if err != nil {
		t.Fatalf("transform failed: %v", err)
	}

	expected := `{"a":{"b":{"c":{"d":"new_value"}}}}`
	assertJSONEqual(t, expected, string(output))
}

func TestJSONPathCache(t *testing.T) {
	cache := NewJSONPathCache(10)

	// Add some paths
	cache.Set("user.name")
	cache.Set("user.email")

	if cache.Size() != 2 {
		t.Errorf("expected size 2, got %d", cache.Size())
	}

	// Test eviction
	for i := 0; i < 20; i++ {
		cache.Set(string(rune('a' + i)))
	}

	if cache.Size() > 10 {
		t.Errorf("cache size should not exceed max size, got %d", cache.Size())
	}

	// Test clear
	cache.Clear()
	if cache.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", cache.Size())
	}
}

func TestValidateJSONPath(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"user.name", false},
		{"$.user.name", false},
		{"@.user.name", false},
		{"user", false},
		{"", true},
		{"user name", true},
		{"user\tname", true},
	}

	for _, tt := range tests {
		err := ValidateJSONPath(tt.path)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateJSONPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
		}
	}
}

func TestParseJSONPathOperations(t *testing.T) {
	data := []byte(`[
		{
			"type": "extract",
			"path": "user.email",
			"target": "X-User-Email"
		},
		{
			"type": "set",
			"path": "version",
			"value": "2.0"
		},
		{
			"type": "delete",
			"path": "internal_metadata"
		}
	]`)

	ops, err := ParseJSONPathOperations(data)
	if err != nil {
		t.Fatalf("failed to parse operations: %v", err)
	}

	if len(ops) != 3 {
		t.Errorf("expected 3 operations, got %d", len(ops))
	}

	if ops[0].Type != JSONPathExtract {
		t.Errorf("expected extract type, got %v", ops[0].Type)
	}
	if ops[0].Target != "X-User-Email" {
		t.Errorf("expected X-User-Email target, got %v", ops[0].Target)
	}
}

func TestParseJSONPathOperations_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "extract without target",
			data: `[{"type": "extract", "path": "user.email"}]`,
		},
		{
			name: "set without value",
			data: `[{"type": "set", "path": "field"}]`,
		},
		{
			name: "copy without target",
			data: `[{"type": "copy", "path": "field"}]`,
		},
		{
			name: "unknown type",
			data: `[{"type": "unknown", "path": "field"}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseJSONPathOperations([]byte(tt.data))
			if err == nil {
				t.Error("expected error for invalid operation")
			}
		})
	}
}

func TestJSONPathTransform_ExtractNumbers(t *testing.T) {
	input := []byte(`{"count": 42, "price": 99.99, "active": true}`)
	
	transform := NewJSONPathTransform([]JSONPathOperation{
		{
			Type:   JSONPathExtract,
			Path:   "count",
			Target: "X-Count",
		},
		{
			Type:   JSONPathExtract,
			Path:   "price",
			Target: "X-Price",
		},
		{
			Type:   JSONPathExtract,
			Path:   "active",
			Target: "X-Active",
		},
	})

	headers := transform.ExtractToHeaders(input)

	if headers["X-Count"] != "42" {
		t.Errorf("expected count 42, got: %v", headers["X-Count"])
	}
	if headers["X-Price"] != "99.99" {
		t.Errorf("expected price 99.99, got: %v", headers["X-Price"])
	}
	if headers["X-Active"] != "true" {
		t.Errorf("expected active true, got: %v", headers["X-Active"])
	}
}

