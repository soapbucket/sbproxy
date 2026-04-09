package streaming

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JSONSchemaValidator performs basic JSON Schema validation for event payloads.
// It supports validating type, required fields, and property types.
type JSONSchemaValidator struct {
	schema map[string]any
}

// NewJSONSchemaValidator parses a JSON Schema from raw bytes and returns a validator.
func NewJSONSchemaValidator(schemaJSON []byte) (*JSONSchemaValidator, error) {
	var schema map[string]any
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		return nil, fmt.Errorf("streaming: invalid JSON schema: %w", err)
	}

	// Validate that the schema itself has a sensible structure.
	if t, ok := schema["type"]; ok {
		ts, isStr := t.(string)
		if !isStr {
			return nil, fmt.Errorf("streaming: schema 'type' must be a string")
		}
		validTypes := map[string]bool{
			"object": true, "array": true, "string": true,
			"number": true, "integer": true, "boolean": true, "null": true,
		}
		if !validTypes[ts] {
			return nil, fmt.Errorf("streaming: unsupported schema type: %s", ts)
		}
	}

	return &JSONSchemaValidator{schema: schema}, nil
}

// Validate checks data against the JSON Schema.
func (v *JSONSchemaValidator) Validate(data []byte) error {
	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("streaming: invalid JSON payload: %w", err)
	}

	return v.validateValue(parsed, v.schema, "")
}

func (v *JSONSchemaValidator) validateValue(value any, schema map[string]any, path string) error {
	// Check type constraint.
	if schemaType, ok := schema["type"].(string); ok {
		if err := v.checkType(value, schemaType, path); err != nil {
			return err
		}
	}

	// For object types, check required fields and property types.
	if isObject(schema) {
		obj, ok := value.(map[string]any)
		if !ok {
			return nil // Type mismatch already caught above.
		}

		// Check required fields.
		if required, ok := schema["required"].([]any); ok {
			for _, r := range required {
				fieldName, isStr := r.(string)
				if !isStr {
					continue
				}
				if _, exists := obj[fieldName]; !exists {
					fieldPath := joinPath(path, fieldName)
					return fmt.Errorf("streaming: missing required field: %s", fieldPath)
				}
			}
		}

		// Check property types.
		if properties, ok := schema["properties"].(map[string]any); ok {
			for propName, propSchema := range properties {
				propVal, exists := obj[propName]
				if !exists {
					continue
				}
				propSchemaMap, isMap := propSchema.(map[string]any)
				if !isMap {
					continue
				}
				fieldPath := joinPath(path, propName)
				if err := v.validateValue(propVal, propSchemaMap, fieldPath); err != nil {
					return err
				}
			}
		}
	}

	// For array types, validate items.
	if isArray(schema) {
		arr, ok := value.([]any)
		if !ok {
			return nil
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for i, elem := range arr {
				elemPath := fmt.Sprintf("%s[%d]", path, i)
				if err := v.validateValue(elem, items, elemPath); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (v *JSONSchemaValidator) checkType(value any, expectedType string, path string) error {
	prefix := "streaming: "
	if path != "" {
		prefix = fmt.Sprintf("streaming: field %s: ", path)
	}

	switch expectedType {
	case "object":
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("%sexpected object, got %s", prefix, jsonTypeName(value))
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return fmt.Errorf("%sexpected array, got %s", prefix, jsonTypeName(value))
		}
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%sexpected string, got %s", prefix, jsonTypeName(value))
		}
	case "number":
		if _, ok := value.(float64); !ok {
			return fmt.Errorf("%sexpected number, got %s", prefix, jsonTypeName(value))
		}
	case "integer":
		f, ok := value.(float64)
		if !ok {
			return fmt.Errorf("%sexpected integer, got %s", prefix, jsonTypeName(value))
		}
		if f != float64(int64(f)) {
			return fmt.Errorf("%sexpected integer, got float", prefix)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%sexpected boolean, got %s", prefix, jsonTypeName(value))
		}
	case "null":
		if value != nil {
			return fmt.Errorf("%sexpected null, got %s", prefix, jsonTypeName(value))
		}
	}

	return nil
}

func isObject(schema map[string]any) bool {
	t, _ := schema["type"].(string)
	return t == "object"
}

func isArray(schema map[string]any) bool {
	t, _ := schema["type"].(string)
	return t == "array"
}

func jsonTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func joinPath(base, field string) string {
	if base == "" {
		return field
	}
	return strings.Join([]string{base, field}, ".")
}
