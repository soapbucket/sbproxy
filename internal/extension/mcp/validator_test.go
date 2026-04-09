package mcp

import (
	"encoding/json"
	"testing"
)

func TestSchemaValidator_Validate(t *testing.T) {
	tools := []ToolConfig{
		{
			Name: "test_tool",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"name": {"type": "string"},
					"age": {"type": "integer"},
					"active": {"type": "boolean"}
				},
				"required": ["name"]
			}`),
		},
		{
			Name:        "no_schema_tool",
			InputSchema: nil,
		},
	}

	validator, err := NewSchemaValidator(tools)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	t.Run("valid arguments", func(t *testing.T) {
		args := map[string]interface{}{
			"name":   "John",
			"age":    float64(30),
			"active": true,
		}
		if mcpErr := validator.Validate("test_tool", args); mcpErr != nil {
			t.Errorf("Unexpected validation error: %v", mcpErr)
		}
	})

	t.Run("missing required field", func(t *testing.T) {
		args := map[string]interface{}{
			"age": float64(30),
		}
		mcpErr := validator.Validate("test_tool", args)
		if mcpErr == nil {
			t.Error("Expected validation error for missing required field")
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		args := map[string]interface{}{
			"name": 123, // Should be string
		}
		mcpErr := validator.Validate("test_tool", args)
		if mcpErr == nil {
			t.Error("Expected validation error for wrong type")
		}
	})

	t.Run("no schema - accepts anything", func(t *testing.T) {
		args := map[string]interface{}{
			"anything": "goes",
		}
		if mcpErr := validator.Validate("no_schema_tool", args); mcpErr != nil {
			t.Errorf("Tool without schema should accept any arguments: %v", mcpErr)
		}
	})

	t.Run("unknown tool - no schema", func(t *testing.T) {
		args := map[string]interface{}{}
		if mcpErr := validator.Validate("unknown_tool", args); mcpErr != nil {
			t.Errorf("Unknown tool should accept any arguments: %v", mcpErr)
		}
	})
}

func TestSchemaValidator_HasSchema(t *testing.T) {
	tools := []ToolConfig{
		{
			Name:        "with_schema",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		},
		{
			Name:        "without_schema",
			InputSchema: nil,
		},
	}

	validator, _ := NewSchemaValidator(tools)

	if !validator.HasSchema("with_schema") {
		t.Error("Expected HasSchema() = true for tool with schema")
	}

	if validator.HasSchema("without_schema") {
		t.Error("Expected HasSchema() = false for tool without schema")
	}

	if validator.HasSchema("nonexistent") {
		t.Error("Expected HasSchema() = false for nonexistent tool")
	}
}

func TestJSONSchema_ValidateString(t *testing.T) {
	schema := &JSONSchema{
		Type:      "string",
		MinLength: intPtr(3),
		MaxLength: intPtr(10),
	}

	t.Run("valid string", func(t *testing.T) {
		errs := schema.Validate("hello")
		if len(errs) > 0 {
			t.Errorf("Unexpected errors: %v", errs)
		}
	})

	t.Run("too short", func(t *testing.T) {
		errs := schema.Validate("hi")
		if len(errs) == 0 {
			t.Error("Expected minLength error")
		}
	})

	t.Run("too long", func(t *testing.T) {
		errs := schema.Validate("this is too long")
		if len(errs) == 0 {
			t.Error("Expected maxLength error")
		}
	})
}

func TestJSONSchema_ValidateNumber(t *testing.T) {
	schema := &JSONSchema{
		Type:    "number",
		Minimum: float64Ptr(0),
		Maximum: float64Ptr(100),
	}

	t.Run("valid number", func(t *testing.T) {
		errs := schema.Validate(float64(50))
		if len(errs) > 0 {
			t.Errorf("Unexpected errors: %v", errs)
		}
	})

	t.Run("below minimum", func(t *testing.T) {
		errs := schema.Validate(float64(-5))
		if len(errs) == 0 {
			t.Error("Expected minimum error")
		}
	})

	t.Run("above maximum", func(t *testing.T) {
		errs := schema.Validate(float64(150))
		if len(errs) == 0 {
			t.Error("Expected maximum error")
		}
	})
}

func TestJSONSchema_ValidateInteger(t *testing.T) {
	schema := &JSONSchema{
		Type: "integer",
	}

	t.Run("valid integer", func(t *testing.T) {
		errs := schema.Validate(float64(42))
		if len(errs) > 0 {
			t.Errorf("Unexpected errors: %v", errs)
		}
	})

	t.Run("float not integer", func(t *testing.T) {
		errs := schema.Validate(float64(3.14))
		if len(errs) == 0 {
			t.Error("Expected error for float instead of integer")
		}
	})
}

func TestJSONSchema_ValidateObject(t *testing.T) {
	schema := &JSONSchema{
		Type: "object",
		Properties: map[string]*JSONSchema{
			"name": {Type: "string"},
			"age":  {Type: "number"},
		},
		Required: []string{"name"},
	}

	t.Run("valid object", func(t *testing.T) {
		obj := map[string]interface{}{
			"name": "John",
			"age":  float64(30),
		}
		errs := schema.Validate(obj)
		if len(errs) > 0 {
			t.Errorf("Unexpected errors: %v", errs)
		}
	})

	t.Run("missing required", func(t *testing.T) {
		obj := map[string]interface{}{
			"age": float64(30),
		}
		errs := schema.Validate(obj)
		if len(errs) == 0 {
			t.Error("Expected error for missing required field")
		}
	})

	t.Run("wrong property type", func(t *testing.T) {
		obj := map[string]interface{}{
			"name": 123, // Should be string
		}
		errs := schema.Validate(obj)
		if len(errs) == 0 {
			t.Error("Expected error for wrong property type")
		}
	})
}

func TestJSONSchema_ValidateArray(t *testing.T) {
	schema := &JSONSchema{
		Type:     "array",
		MinItems: intPtr(1),
		MaxItems: intPtr(5),
		Items:    &JSONSchema{Type: "string"},
	}

	t.Run("valid array", func(t *testing.T) {
		arr := []interface{}{"a", "b", "c"}
		errs := schema.Validate(arr)
		if len(errs) > 0 {
			t.Errorf("Unexpected errors: %v", errs)
		}
	})

	t.Run("empty array", func(t *testing.T) {
		arr := []interface{}{}
		errs := schema.Validate(arr)
		if len(errs) == 0 {
			t.Error("Expected minItems error")
		}
	})

	t.Run("too many items", func(t *testing.T) {
		arr := []interface{}{"a", "b", "c", "d", "e", "f"}
		errs := schema.Validate(arr)
		if len(errs) == 0 {
			t.Error("Expected maxItems error")
		}
	})

	t.Run("wrong item type", func(t *testing.T) {
		arr := []interface{}{"a", 123, "c"} // 123 is not a string
		errs := schema.Validate(arr)
		if len(errs) == 0 {
			t.Error("Expected error for wrong item type")
		}
	})
}

func TestJSONSchema_ValidateEnum(t *testing.T) {
	schema := &JSONSchema{
		Type: "string",
		Enum: []interface{}{"red", "green", "blue"},
	}

	t.Run("valid enum value", func(t *testing.T) {
		errs := schema.Validate("red")
		if len(errs) > 0 {
			t.Errorf("Unexpected errors: %v", errs)
		}
	})

	t.Run("invalid enum value", func(t *testing.T) {
		errs := schema.Validate("yellow")
		if len(errs) == 0 {
			t.Error("Expected enum error")
		}
	})
}

func TestJSONSchema_ValidateBoolean(t *testing.T) {
	schema := &JSONSchema{
		Type: "boolean",
	}

	t.Run("valid boolean", func(t *testing.T) {
		errs := schema.Validate(true)
		if len(errs) > 0 {
			t.Errorf("Unexpected errors: %v", errs)
		}
	})

	t.Run("not a boolean", func(t *testing.T) {
		errs := schema.Validate("true")
		if len(errs) == 0 {
			t.Error("Expected type error")
		}
	})
}

func TestJSONSchema_ValidateNull(t *testing.T) {
	schema := &JSONSchema{
		Type: "null",
	}

	t.Run("null value", func(t *testing.T) {
		errs := schema.Validate(nil)
		if len(errs) > 0 {
			t.Errorf("Unexpected errors: %v", errs)
		}
	})

	t.Run("non-null value", func(t *testing.T) {
		errs := schema.Validate("something")
		if len(errs) == 0 {
			t.Error("Expected type error for non-null")
		}
	})
}

func TestJSONSchema_NestedValidation(t *testing.T) {
	schema := &JSONSchema{
		Type: "object",
		Properties: map[string]*JSONSchema{
			"user": {
				Type: "object",
				Properties: map[string]*JSONSchema{
					"name":  {Type: "string"},
					"email": {Type: "string"},
				},
				Required: []string{"name", "email"},
			},
			"settings": {
				Type: "object",
				Properties: map[string]*JSONSchema{
					"theme": {
						Type: "string",
						Enum: []interface{}{"light", "dark"},
					},
				},
			},
		},
		Required: []string{"user"},
	}

	t.Run("valid nested object", func(t *testing.T) {
		obj := map[string]interface{}{
			"user": map[string]interface{}{
				"name":  "John",
				"email": "john@example.com",
			},
			"settings": map[string]interface{}{
				"theme": "dark",
			},
		}
		errs := schema.Validate(obj)
		if len(errs) > 0 {
			t.Errorf("Unexpected errors: %v", errs)
		}
	})

	t.Run("missing nested required", func(t *testing.T) {
		obj := map[string]interface{}{
			"user": map[string]interface{}{
				"name": "John",
				// Missing email
			},
		}
		errs := schema.Validate(obj)
		if len(errs) == 0 {
			t.Error("Expected error for missing nested required field")
		}
	})

	t.Run("invalid nested enum", func(t *testing.T) {
		obj := map[string]interface{}{
			"user": map[string]interface{}{
				"name":  "John",
				"email": "john@example.com",
			},
			"settings": map[string]interface{}{
				"theme": "purple", // Invalid enum value
			},
		}
		errs := schema.Validate(obj)
		if len(errs) == 0 {
			t.Error("Expected error for invalid nested enum")
		}
	})
}

func TestParseJSONSchema(t *testing.T) {
	t.Run("valid schema", func(t *testing.T) {
		data := []byte(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
		schema, err := ParseJSONSchema(data)
		if err != nil {
			t.Fatalf("Failed to parse: %v", err)
		}
		if schema.Type != "object" {
			t.Errorf("Expected type 'object', got %s", schema.Type)
		}
		if len(schema.Required) != 1 {
			t.Error("Expected 1 required field")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		data := []byte(`{invalid}`)
		_, err := ParseJSONSchema(data)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}

func TestGetJSONType(t *testing.T) {
	tests := []struct {
		value    interface{}
		expected string
	}{
		{nil, "null"},
		{map[string]interface{}{}, "object"},
		{[]interface{}{}, "array"},
		{"string", "string"},
		{float64(123), "number"},
		{true, "boolean"},
		{struct{}{}, "unknown"},
	}

	for _, tt := range tests {
		result := getJSONType(tt.value)
		if result != tt.expected {
			t.Errorf("getJSONType(%v) = %s, expected %s", tt.value, result, tt.expected)
		}
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		value    interface{}
		expected float64
		ok       bool
	}{
		{float64(3.14), 3.14, true},
		{float32(2.5), 2.5, true},
		{int(42), 42.0, true},
		{int64(100), 100.0, true},
		{int32(50), 50.0, true},
		{"string", 0, false},
		{nil, 0, false},
	}

	for _, tt := range tests {
		result, ok := toFloat64(tt.value)
		if ok != tt.ok {
			t.Errorf("toFloat64(%v) ok = %v, expected %v", tt.value, ok, tt.ok)
		}
		if ok && result != tt.expected {
			t.Errorf("toFloat64(%v) = %v, expected %v", tt.value, result, tt.expected)
		}
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct {
		base     string
		field    string
		expected string
	}{
		{"", "field", "field"},
		{"root", "field", "root.field"},
		{"a.b", "c", "a.b.c"},
	}

	for _, tt := range tests {
		result := joinPath(tt.base, tt.field)
		if result != tt.expected {
			t.Errorf("joinPath(%q, %q) = %q, expected %q", tt.base, tt.field, result, tt.expected)
		}
	}
}

func TestFormatError(t *testing.T) {
	tests := []struct {
		path     string
		message  string
		expected string
	}{
		{"", "error message", "error message"},
		{"field", "is required", "field: is required"},
		{"a.b.c", "invalid", "a.b.c: invalid"},
	}

	for _, tt := range tests {
		result := formatError(tt.path, tt.message)
		if result != tt.expected {
			t.Errorf("formatError(%q, %q) = %q, expected %q", tt.path, tt.message, result, tt.expected)
		}
	}
}

// Helpers
func intPtr(i int) *int {
	return &i
}

func float64Ptr(f float64) *float64 {
	return &f
}
