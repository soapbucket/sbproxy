// Package mcp implements the Model Context Protocol (MCP) for AI tool and resource integration.
package mcp

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// =============================================================================
// Schema Validator
// =============================================================================

// SchemaValidator validates tool arguments against JSON Schema.
type SchemaValidator struct {
	schemas map[string]*JSONSchema
}

// NewSchemaValidator creates a new schema validator from tool configurations.
func NewSchemaValidator(tools []ToolConfig) (*SchemaValidator, error) {
	v := &SchemaValidator{
		schemas: make(map[string]*JSONSchema),
	}

	for _, tool := range tools {
		if len(tool.InputSchema) == 0 {
			continue
		}

		schema, err := ParseJSONSchema(tool.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("invalid schema for tool %s: %w", tool.Name, err)
		}

		v.schemas[tool.Name] = schema
	}

	return v, nil
}

// Validate validates tool arguments against the tool's schema.
func (v *SchemaValidator) Validate(toolName string, args map[string]interface{}) *MCPError {
	schema, ok := v.schemas[toolName]
	if !ok {
		// No schema defined - allow any arguments
		return nil
	}

	errors := schema.Validate(args)
	if len(errors) > 0 {
		return NewValidationError(toolName, errors)
	}

	return nil
}

// HasSchema returns true if a schema is registered for the tool.
func (v *SchemaValidator) HasSchema(toolName string) bool {
	_, ok := v.schemas[toolName]
	return ok
}

// =============================================================================
// JSON Schema (Simplified Implementation)
// =============================================================================

// JSONSchema represents a simplified JSON Schema for validation.
type JSONSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]*JSONSchema `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
	Items      *JSONSchema            `json:"items,omitempty"`

	// String constraints
	MinLength *int          `json:"minLength,omitempty"`
	MaxLength *int          `json:"maxLength,omitempty"`
	Pattern   string        `json:"pattern,omitempty"`
	Enum      []interface{} `json:"enum,omitempty"`

	// Number constraints
	Minimum          *float64 `json:"minimum,omitempty"`
	Maximum          *float64 `json:"maximum,omitempty"`
	ExclusiveMinimum *float64 `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum *float64 `json:"exclusiveMaximum,omitempty"`

	// Array constraints
	MinItems    *int `json:"minItems,omitempty"`
	MaxItems    *int `json:"maxItems,omitempty"`
	UniqueItems bool `json:"uniqueItems,omitempty"`

	// Metadata
	Description string      `json:"description,omitempty"`
	Default     interface{} `json:"default,omitempty"`
}

// ParseJSONSchema parses a JSON Schema from bytes.
func ParseJSONSchema(data []byte) (*JSONSchema, error) {
	var schema JSONSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("failed to parse schema: %w", err)
	}
	return &schema, nil
}

// Validate validates a value against this schema.
func (s *JSONSchema) Validate(value interface{}) []string {
	return s.validateValue("", value)
}

func (s *JSONSchema) validateValue(path string, value interface{}) []string {
	var errors []string

	// Handle nil value
	if value == nil {
		if s.Type != "" && s.Type != "null" {
			errors = append(errors, formatError(path, "value is required"))
		}
		return errors
	}

	// Type validation
	if s.Type != "" {
		typeErrors := s.validateType(path, value)
		errors = append(errors, typeErrors...)
		if len(typeErrors) > 0 {
			return errors // Stop validation if type is wrong
		}
	}

	// Type-specific validation
	switch s.Type {
	case "object":
		if obj, ok := value.(map[string]interface{}); ok {
			errors = append(errors, s.validateObject(path, obj)...)
		}
	case "array":
		if arr, ok := value.([]interface{}); ok {
			errors = append(errors, s.validateArray(path, arr)...)
		}
	case "string":
		if str, ok := value.(string); ok {
			errors = append(errors, s.validateString(path, str)...)
		}
	case "number", "integer":
		errors = append(errors, s.validateNumber(path, value)...)
	}

	// Enum validation
	if len(s.Enum) > 0 {
		errors = append(errors, s.validateEnum(path, value)...)
	}

	return errors
}

func (s *JSONSchema) validateType(path string, value interface{}) []string {
	var errors []string

	actualType := getJSONType(value)

	switch s.Type {
	case "object":
		if actualType != "object" {
			errors = append(errors, formatError(path, fmt.Sprintf("expected object, got %s", actualType)))
		}
	case "array":
		if actualType != "array" {
			errors = append(errors, formatError(path, fmt.Sprintf("expected array, got %s", actualType)))
		}
	case "string":
		if actualType != "string" {
			errors = append(errors, formatError(path, fmt.Sprintf("expected string, got %s", actualType)))
		}
	case "number":
		if actualType != "number" {
			errors = append(errors, formatError(path, fmt.Sprintf("expected number, got %s", actualType)))
		}
	case "integer":
		if actualType != "number" {
			errors = append(errors, formatError(path, fmt.Sprintf("expected integer, got %s", actualType)))
		} else if num, ok := value.(float64); ok {
			if num != float64(int64(num)) {
				errors = append(errors, formatError(path, "expected integer, got float"))
			}
		}
	case "boolean":
		if actualType != "boolean" {
			errors = append(errors, formatError(path, fmt.Sprintf("expected boolean, got %s", actualType)))
		}
	case "null":
		if value != nil {
			errors = append(errors, formatError(path, fmt.Sprintf("expected null, got %s", actualType)))
		}
	}

	return errors
}

func (s *JSONSchema) validateObject(path string, obj map[string]interface{}) []string {
	var errors []string

	// Check required fields
	for _, required := range s.Required {
		if _, ok := obj[required]; !ok {
			errors = append(errors, formatError(joinPath(path, required), "is required"))
		}
	}

	// Validate properties
	for propName, propSchema := range s.Properties {
		if propValue, ok := obj[propName]; ok {
			propErrors := propSchema.validateValue(joinPath(path, propName), propValue)
			errors = append(errors, propErrors...)
		}
	}

	return errors
}

func (s *JSONSchema) validateArray(path string, arr []interface{}) []string {
	var errors []string

	// MinItems validation
	if s.MinItems != nil && len(arr) < *s.MinItems {
		errors = append(errors, formatError(path, fmt.Sprintf("array must have at least %d items", *s.MinItems)))
	}

	// MaxItems validation
	if s.MaxItems != nil && len(arr) > *s.MaxItems {
		errors = append(errors, formatError(path, fmt.Sprintf("array must have at most %d items", *s.MaxItems)))
	}

	// Items validation
	if s.Items != nil {
		for i, item := range arr {
			itemErrors := s.Items.validateValue(fmt.Sprintf("%s[%d]", path, i), item)
			errors = append(errors, itemErrors...)
		}
	}

	return errors
}

func (s *JSONSchema) validateString(path string, str string) []string {
	var errors []string

	// MinLength validation
	if s.MinLength != nil && len(str) < *s.MinLength {
		errors = append(errors, formatError(path, fmt.Sprintf("string must be at least %d characters", *s.MinLength)))
	}

	// MaxLength validation
	if s.MaxLength != nil && len(str) > *s.MaxLength {
		errors = append(errors, formatError(path, fmt.Sprintf("string must be at most %d characters", *s.MaxLength)))
	}

	// Pattern validation would require regex - simplified here
	// For production, use a proper JSON Schema library

	return errors
}

func (s *JSONSchema) validateNumber(path string, value interface{}) []string {
	var errors []string

	num, ok := toFloat64(value)
	if !ok {
		return errors // Type validation already handled
	}

	// Minimum validation
	if s.Minimum != nil && num < *s.Minimum {
		errors = append(errors, formatError(path, fmt.Sprintf("must be >= %v", *s.Minimum)))
	}

	// Maximum validation
	if s.Maximum != nil && num > *s.Maximum {
		errors = append(errors, formatError(path, fmt.Sprintf("must be <= %v", *s.Maximum)))
	}

	// ExclusiveMinimum validation
	if s.ExclusiveMinimum != nil && num <= *s.ExclusiveMinimum {
		errors = append(errors, formatError(path, fmt.Sprintf("must be > %v", *s.ExclusiveMinimum)))
	}

	// ExclusiveMaximum validation
	if s.ExclusiveMaximum != nil && num >= *s.ExclusiveMaximum {
		errors = append(errors, formatError(path, fmt.Sprintf("must be < %v", *s.ExclusiveMaximum)))
	}

	return errors
}

func (s *JSONSchema) validateEnum(path string, value interface{}) []string {
	var errors []string

	for _, enumValue := range s.Enum {
		if reflect.DeepEqual(value, enumValue) {
			return nil // Found a match
		}
	}

	errors = append(errors, formatError(path, fmt.Sprintf("must be one of: %v", s.Enum)))
	return errors
}

// =============================================================================
// Helper Functions
// =============================================================================

func getJSONType(value interface{}) string {
	if value == nil {
		return "null"
	}

	switch value.(type) {
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "array"
	case string:
		return "string"
	case float64, float32, int, int64, int32:
		return "number"
	case bool:
		return "boolean"
	default:
		return "unknown"
	}
}

func toFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	default:
		return 0, false
	}
}

func joinPath(base, field string) string {
	if base == "" {
		return field
	}
	return base + "." + field
}

func formatError(path, message string) string {
	if path == "" {
		return message
	}
	return fmt.Sprintf("%s: %s", path, message)
}
