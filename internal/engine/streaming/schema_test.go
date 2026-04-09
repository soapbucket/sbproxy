package streaming

import (
	"strings"
	"testing"
)

func TestJSONSchemaValidator_Valid(t *testing.T) {
	schema := []byte(`{
		"type": "object",
		"required": ["user_id", "event"],
		"properties": {
			"user_id": {"type": "string"},
			"event": {"type": "string"},
			"amount": {"type": "number"},
			"active": {"type": "boolean"}
		}
	}`)

	v, err := NewJSONSchemaValidator(schema)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	data := []byte(`{"user_id": "u-123", "event": "purchase", "amount": 49.99, "active": true}`)
	if err := v.Validate(data); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

func TestJSONSchemaValidator_MissingRequired(t *testing.T) {
	schema := []byte(`{
		"type": "object",
		"required": ["user_id", "event"],
		"properties": {
			"user_id": {"type": "string"},
			"event": {"type": "string"}
		}
	}`)

	v, err := NewJSONSchemaValidator(schema)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	data := []byte(`{"user_id": "u-123"}`)
	err = v.Validate(data)
	if err == nil {
		t.Fatal("expected error for missing required field, got nil")
	}
	if !strings.Contains(err.Error(), "missing required field") {
		t.Errorf("expected 'missing required field' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "event") {
		t.Errorf("expected 'event' field name in error, got: %v", err)
	}
}

func TestJSONSchemaValidator_WrongType(t *testing.T) {
	schema := []byte(`{
		"type": "object",
		"properties": {
			"count": {"type": "integer"},
			"name": {"type": "string"},
			"tags": {"type": "array"}
		}
	}`)

	v, err := NewJSONSchemaValidator(schema)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name:    "string instead of integer",
			data:    `{"count": "not-a-number"}`,
			wantErr: "expected integer",
		},
		{
			name:    "number instead of string",
			data:    `{"name": 42}`,
			wantErr: "expected string",
		},
		{
			name:    "string instead of array",
			data:    `{"tags": "not-an-array"}`,
			wantErr: "expected array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate([]byte(tt.data))
			if err == nil {
				t.Fatal("expected type error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestJSONSchemaValidator_InvalidSchema(t *testing.T) {
	tests := []struct {
		name   string
		schema string
	}{
		{
			name:   "not json",
			schema: `this is not json`,
		},
		{
			name:   "invalid type value",
			schema: `{"type": "foobar"}`,
		},
		{
			name:   "type is not string",
			schema: `{"type": 42}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJSONSchemaValidator([]byte(tt.schema))
			if err == nil {
				t.Fatal("expected error for invalid schema, got nil")
			}
		})
	}
}

func TestJSONSchemaValidator_InvalidPayload(t *testing.T) {
	schema := []byte(`{"type": "object"}`)
	v, err := NewJSONSchemaValidator(schema)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	err = v.Validate([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON payload, got nil")
	}
	if !strings.Contains(err.Error(), "invalid JSON payload") {
		t.Errorf("expected 'invalid JSON payload' in error, got: %v", err)
	}
}

func TestJSONSchemaValidator_NestedObject(t *testing.T) {
	schema := []byte(`{
		"type": "object",
		"properties": {
			"address": {
				"type": "object",
				"required": ["city"],
				"properties": {
					"city": {"type": "string"},
					"zip": {"type": "string"}
				}
			}
		}
	}`)

	v, err := NewJSONSchemaValidator(schema)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Valid nested object.
	err = v.Validate([]byte(`{"address": {"city": "Portland", "zip": "97201"}}`))
	if err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	// Missing required nested field.
	err = v.Validate([]byte(`{"address": {"zip": "97201"}}`))
	if err == nil {
		t.Fatal("expected error for missing nested required field")
	}
	if !strings.Contains(err.Error(), "address.city") {
		t.Errorf("expected 'address.city' in error path, got: %v", err)
	}
}

func TestJSONSchemaValidator_ArrayItems(t *testing.T) {
	schema := []byte(`{
		"type": "object",
		"properties": {
			"scores": {
				"type": "array",
				"items": {"type": "number"}
			}
		}
	}`)

	v, err := NewJSONSchemaValidator(schema)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Valid array.
	err = v.Validate([]byte(`{"scores": [1.5, 2.0, 3.7]}`))
	if err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	// Invalid array element.
	err = v.Validate([]byte(`{"scores": [1.5, "bad", 3.7]}`))
	if err == nil {
		t.Fatal("expected error for wrong array element type")
	}
	if !strings.Contains(err.Error(), "expected number") {
		t.Errorf("expected 'expected number' in error, got: %v", err)
	}
}

func TestJSONSchemaValidator_TopLevelTypeMismatch(t *testing.T) {
	schema := []byte(`{"type": "object"}`)
	v, err := NewJSONSchemaValidator(schema)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	err = v.Validate([]byte(`"just a string"`))
	if err == nil {
		t.Fatal("expected error for top-level type mismatch")
	}
	if !strings.Contains(err.Error(), "expected object") {
		t.Errorf("expected 'expected object' in error, got: %v", err)
	}
}
