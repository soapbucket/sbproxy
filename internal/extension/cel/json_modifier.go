// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"github.com/soapbucket/sbproxy/internal/util"
	json "github.com/goccy/go-json"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// JSONModificationResult represents the modifications to be applied to a JSON object.
type JSONModificationResult struct {
	// SetFields contains fields to set (replaces existing values)
	SetFields map[string]interface{}
	// DeleteFields contains field names to delete
	DeleteFields []string
	// ModifiedJSON is the complete modified JSON object
	ModifiedJSON map[string]interface{}
}

// JSONModifier modifies JSON objects based on CEL expressions.
type JSONModifier interface {
	// ModifyJSON evaluates the CEL expression and applies the modifications to the JSON object.
	// Returns the modified JSON object and any error that occurred.
	ModifyJSON(map[string]interface{}) (map[string]interface{}, error)
}

type jsonModifier struct {
	cel.Program
}

// ModifyJSON evaluates the CEL expression and applies modifications to the JSON object
func (m *jsonModifier) ModifyJSON(jsonObj map[string]interface{}) (map[string]interface{}, error) {
	vars := getJSONModifierVars(jsonObj)
	
	// Measure CEL execution time
	startTime := time.Now()
	out, _, err := m.Eval(vars)
	duration := time.Since(startTime).Seconds()
	
	// Record CEL execution time (origin unknown for JSON modifications)
	metric.CELExecutionTime("unknown", "json_modifier", duration)
	
	if err != nil {
		slog.Debug("error evaluating JSON expression", "error", err)
		return jsonObj, err
	}

	// Extract the modifications from the CEL result
	modifications, err := extractJSONModifications(out)
	if err != nil {
		slog.Debug("error extracting JSON modifications", "error", err)
		return jsonObj, err
	}

	// Apply modifications to the JSON object
	modifiedJSON, err := applyJSONModifications(jsonObj, modifications)
	if err != nil {
		slog.Debug("error applying JSON modifications", "error", err)
		return jsonObj, err
	}

	return modifiedJSON, nil
}

// getJSONModifierVars creates CEL variables from a JSON object for the modifier.
func getJSONModifierVars(jsonObj map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"json": jsonObj,
	}
}

// NewJSONModifier creates a new CEL JSON modifier for JSON objects.
// The expression must return a map with modification instructions.
//
// The expression has access to:
//   - json: The input JSON object as a map[string]interface{}
//
// The expression must return a map with the following optional keys:
//   - set_fields: map[string]interface{} - Fields to set (replaces existing)
//   - delete_fields: []string - Field names to delete
//   - modified_json: map[string]interface{} - Complete modified JSON object (overrides other operations)
//
// Example expressions:
//
//	{
//	  "set_fields": {"new_field": "value", "updated_field": 123}
//	}
//
//	{
//	  "delete_fields": ["old_field", "sensitive_data"]
//	}
//
//	{
//	  "set_fields": {"status": "modified"},
//	  "delete_fields": ["internal_id"]
//	}
//
//	{
//	  "modified_json": {
//	    "id": json.id,
//	    "name": json.name,
//	    "status": "processed"
//	  }
//	}
func NewJSONModifier(expr string) (JSONModifier, error) {
	env, err := getJSONEnv()
	if err != nil {
		return nil, err
	}

	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if ast == nil {
		return nil, nil
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return &jsonModifier{Program: program}, nil
}

// extractJSONModifications extracts JSONModificationResult from the CEL evaluation result
func extractJSONModifications(out interface{ Value() interface{} }) (*JSONModificationResult, error) {
	// Convert CEL value to native Go types
	refVal, ok := out.(ref.Val)
	if !ok {
		return nil, fmt.Errorf("cel: expected ref.Val, got %T", out)
	}

	// Use reflection to get the native value
	nativeMap, err := refVal.ConvertToNative(reflect.TypeOf(map[string]interface{}{}))
	if err != nil {
		return nil, fmt.Errorf("cel: failed to convert to native: %w", err)
	}

	var resultMap map[string]interface{}
	switch m := nativeMap.(type) {
	case map[string]interface{}:
		resultMap = m
	case map[interface{}]interface{}:
		resultMap = make(map[string]interface{}, len(m))
		for k, v := range m {
			resultMap[fmt.Sprintf("%v", k)] = v
		}
	default:
		return nil, fmt.Errorf("cel: expected map result, got %T", nativeMap)
	}

	result := &JSONModificationResult{
		SetFields:    make(map[string]interface{}),
		DeleteFields: []string{},
	}

	// Extract set_fields
	if setFieldsVal, ok := resultMap["set_fields"]; ok && setFieldsVal != nil {
		setFields := convertToInterfaceMap(setFieldsVal)
		for k, v := range setFields {
			// Ensure nested values are native types
			result.SetFields[k] = convertToNativeValue(v)
		}
	}

	// Extract delete_fields
	if deleteFieldsVal, ok := resultMap["delete_fields"]; ok && deleteFieldsVal != nil {
		deleteFields := convertToStringSlice(deleteFieldsVal)
		result.DeleteFields = deleteFields
	}

	// Extract modified_json (overrides other operations)
	if modifiedJSONVal, ok := resultMap["modified_json"]; ok && modifiedJSONVal != nil {
		modifiedJSON := convertToInterfaceMap(modifiedJSONVal)
		result.ModifiedJSON = modifiedJSON
	}

	return result, nil
}

// convertToInterfaceMap converts a value to map[string]interface{}
// Recursively converts nested CEL ref.Val types to native Go types
func convertToInterfaceMap(val interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Try direct conversion first
	if m, ok := val.(map[string]interface{}); ok {
		// Recursively convert nested values
		for k, v := range m {
			result[k] = convertToNativeValue(v)
		}
		return result
	}

	// Handle map[interface{}]interface{} (cel-go 0.28+ ConvertToNative output)
	if m, ok := val.(map[interface{}]interface{}); ok {
		for k, v := range m {
			kStr := fmt.Sprintf("%v", k)
			result[kStr] = convertToNativeValue(v)
		}
		return result
	}

	// Handle map[ref.Val]ref.Val (CEL native map type)
	if refMap, ok := val.(map[ref.Val]ref.Val); ok {
		for k, v := range refMap {
			// Convert key to string - use Value() method
			kStr := k.Value().(string)

			// Convert value to native type recursively
			vNative := convertToNativeValue(v.Value())
			result[kStr] = vNative
		}
		return result
	}

	// Try ref.Val (CEL type)
	if refVal, ok := val.(ref.Val); ok {
		if nativeMap, err := refVal.ConvertToNative(reflect.TypeOf(map[string]interface{}{})); err == nil {
			if m, ok := nativeMap.(map[string]interface{}); ok {
				// Recursively convert nested values
				for k, v := range m {
					result[k] = convertToNativeValue(v)
				}
				return result
			}
			// Also handle map[interface{}]interface{} from ConvertToNative
			if m, ok := nativeMap.(map[interface{}]interface{}); ok {
				for k, v := range m {
					kStr := fmt.Sprintf("%v", k)
					result[kStr] = convertToNativeValue(v)
				}
				return result
			}
		}
	}

	return result
}

// convertToNativeValue recursively converts CEL ref.Val types to native Go types
func convertToNativeValue(val interface{}) interface{} {
	// If it's already a native type, return as-is
	switch v := val.(type) {
	case string, bool, float64, int, int64, nil:
		return v
	case []interface{}:
		// Recursively convert slice elements
		result := make([]interface{}, len(v))
		for i, elem := range v {
			result[i] = convertToNativeValue(elem)
		}
		return result
	case map[string]interface{}:
		// Recursively convert nested maps
		result := make(map[string]interface{})
		for k, v := range v {
			result[k] = convertToNativeValue(v)
		}
		return result
	case map[interface{}]interface{}:
		// Handle map[interface{}]interface{} (cel-go 0.28+ ConvertToNative output)
		result := make(map[string]interface{})
		for k, v := range v {
			kStr := fmt.Sprintf("%v", k)
			result[kStr] = convertToNativeValue(v)
		}
		return result
	}

	// Handle map[ref.Val]ref.Val (CEL native map type)
	if refMap, ok := val.(map[ref.Val]ref.Val); ok {
		result := make(map[string]interface{})
		for k, v := range refMap {
			// Convert key to string
			kStr := k.Value().(string)
			// Recursively convert value
			result[kStr] = convertToNativeValue(v.Value())
		}
		return result
	}

	// Try ref.Val (CEL type) - use ConvertToNative
	if refVal, ok := val.(ref.Val); ok {
		// Try to convert to map first
		if nativeMap, err := refVal.ConvertToNative(reflect.TypeOf(map[string]interface{}{})); err == nil {
			if m, ok := nativeMap.(map[string]interface{}); ok {
				return convertToNativeValue(m)
			}
		}
		// Try to convert to slice
		if nativeSlice, err := refVal.ConvertToNative(reflect.TypeOf([]interface{}{})); err == nil {
			if s, ok := nativeSlice.([]interface{}); ok {
				return convertToNativeValue(s)
			}
		}
		// Fall back to Value() method
		return convertToNativeValue(refVal.Value())
	}

	// Try interface with Value() method (for ref.Val wrapped values)
	if refVal, ok := val.(interface{ Value() interface{} }); ok {
		return convertToNativeValue(refVal.Value())
	}

	// Unknown type - return as-is
	return val
}

// applyJSONModifications applies the modifications to the JSON object and returns a new object
func applyJSONModifications(jsonObj map[string]interface{}, mods *JSONModificationResult) (map[string]interface{}, error) {
	// If modified_json is provided, use it directly (already converted to native types)
	if mods.ModifiedJSON != nil {
		// Ensure all nested values are native types
		result := make(map[string]interface{})
		for k, v := range mods.ModifiedJSON {
			result[k] = convertToNativeValue(v)
		}
		return result, nil
	}

	// Clone the JSON object to avoid modifying the original
	modifiedJSON := make(map[string]interface{})
	for k, v := range jsonObj {
		modifiedJSON[k] = v
	}

	// Apply field deletions
	for _, fieldName := range mods.DeleteFields {
		delete(modifiedJSON, fieldName)
	}

	// Apply field sets (replaces existing)
	for k, v := range mods.SetFields {
		modifiedJSON[k] = v
	}

	return modifiedJSON, nil
}

// ApplyJSONModifications is a helper function that applies JSONModificationResult to a JSON object
func ApplyJSONModifications(jsonObj map[string]interface{}, mods *JSONModificationResult) (map[string]interface{}, error) {
	return applyJSONModifications(jsonObj, mods)
}

// ParseJSONModificationExpression parses a CEL expression and returns a JSONModifier
func ParseJSONModificationExpression(expr string) (JSONModifier, error) {
	return NewJSONModifier(expr)
}

// ModifyJSONWithExpression is a convenience function that creates a modifier and applies it to a JSON object
func ModifyJSONWithExpression(jsonObj map[string]interface{}, expr string) (map[string]interface{}, error) {
	modifier, err := NewJSONModifier(expr)
	if err != nil {
		return jsonObj, fmt.Errorf("%w: %v", util.ErrJSONModifierCreationFailed, err)
	}
	return modifier.ModifyJSON(jsonObj)
}

// ModifyJSONString is a convenience function that works with JSON strings
func ModifyJSONString(jsonStr string, expr string) (string, error) {
	// Parse the input JSON
	var jsonObj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonObj); err != nil {
		return jsonStr, fmt.Errorf("%w: %v", util.ErrJSONParseFailed, err)
	}

	// Apply modifications
	modifiedJSON, err := ModifyJSONWithExpression(jsonObj, expr)
	if err != nil {
		return jsonStr, err
	}

	// Marshal back to JSON string
	modifiedBytes, err := json.Marshal(modifiedJSON)
	if err != nil {
		return jsonStr, fmt.Errorf("%w: %v", util.ErrJSONMarshalFailed, err)
	}

	return string(modifiedBytes), nil
}
