// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"fmt"
	"reflect"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
)

// JSONModifier evaluates a compiled CEL expression against a JSON map
// and returns the (possibly transformed) result.
type JSONModifier struct {
	program celgo.Program
	expr    string
}

// CompileJSONModifier compiles a CEL expression for use as a JSON modifier.
// The expression has access to a "json" variable containing the input map.
// It should return a map (which may include a "modified_json" key for full replacement).
func CompileJSONModifier(expr string) (*JSONModifier, error) {
	if expr == "" {
		return nil, nil
	}

	env, err := getJSONEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to get CEL JSON environment: %w", err)
	}

	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("CEL compilation error: %w", iss.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program creation error: %w", err)
	}

	return &JSONModifier{program: program, expr: expr}, nil
}

// ModifyJSON evaluates the CEL expression with the given JSON map as the "json" variable.
//
// The CEL expression should return a map. If the returned map contains a "modified_json"
// key whose value is itself a map, that inner map is used as the complete replacement
// result (matching Lua's modified_json convention). Otherwise the entire returned map
// is used as-is.
func (m *JSONModifier) ModifyJSON(jsonObj map[string]any) (map[string]any, error) {
	out, _, err := m.program.Eval(map[string]any{
		"json": jsonObj,
	})
	if err != nil {
		return jsonObj, fmt.Errorf("CEL evaluation error: %w", err)
	}

	resultMap, err := celValToMap(out)
	if err != nil {
		return jsonObj, err
	}

	// If the expression returned {"modified_json": {...}}, use the inner map
	// as the complete replacement (same convention as Lua's modified_json).
	if modJSON, ok := resultMap["modified_json"]; ok {
		if innerMap, ok2 := modJSON.(map[string]any); ok2 {
			return innerMap, nil
		}
	}

	return resultMap, nil
}

// celValToMap converts a CEL ref.Val to map[string]any with deep conversion
// of all nested maps from map[interface{}]interface{} to map[string]any.
func celValToMap(val ref.Val) (map[string]any, error) {
	nativeMap, err := val.ConvertToNative(reflect.TypeOf(map[string]any{}))
	if err != nil {
		return nil, fmt.Errorf("CEL result conversion error: %w", err)
	}
	top, err := toStringKeyMap(nativeMap)
	if err != nil {
		return nil, err
	}
	return deepConvertMap(top), nil
}

// deepConvertMap recursively converts any map[interface{}]interface{} values
// to map[string]any. CEL's ConvertToNative only converts the top-level map,
// leaving nested maps as map[interface{}]interface{}.
func deepConvertMap(m map[string]any) map[string]any {
	for k, v := range m {
		m[k] = deepConvertValue(v)
	}
	return m
}

// deepConvertValue converts a single value, recursing into maps and slices.
func deepConvertValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepConvertMap(val)
	case map[any]any:
		result := make(map[string]any, len(val))
		for mk, mv := range val {
			result[fmt.Sprintf("%v", mk)] = deepConvertValue(mv)
		}
		return result
	case []any:
		for i, item := range val {
			val[i] = deepConvertValue(item)
		}
		return val
	default:
		return v
	}
}
