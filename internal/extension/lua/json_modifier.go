// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/soapbucket/sbproxy/internal/util"
	"log/slog"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
	lua "github.com/yuin/gopher-lua"
)

// Use global error from common package

// JSONModificationResult represents the modifications to be applied to a JSON object.
type JSONModificationResult struct {
	// SetFields contains fields to set (replaces existing values)
	SetFields map[string]interface{}
	// DeleteFields contains field names to delete
	DeleteFields []string
	// ModifiedJSON is the complete modified JSON object
	ModifiedJSON map[string]interface{}
}

// JSONModifier modifies JSON objects based on Lua scripts.
type JSONModifier interface {
	// ModifyJSON evaluates the Lua script and applies the modifications to the JSON object.
	// Returns the modified JSON object and any error that occurred.
	ModifyJSON(map[string]interface{}) (map[string]interface{}, error)
}

type jsonModifier struct {
	script  string
	wrapped string // wrapped script with function definition
	timeout time.Duration
	useFunc bool // true when script defines function modify_json(data, ctx)
}

// ModifyJSON evaluates the Lua script and applies modifications to the JSON object.
//
// Scripts can use either pattern:
//
// Function-based (preferred, consistent with all other Lua APIs):
//
//	function modify_json(data, ctx)
//	  return { set_fields = { status = "processed" } }
//	end
//
// Bare return (backward compatible, auto-wrapped into function):
//
//	return { set_fields = { status = "processed" } }
//
// In both cases, the input JSON is available as a table. Function-based scripts
// receive it as the `data` parameter. Bare scripts access it via the `json` global.
func (m *jsonModifier) ModifyJSON(jsonObj map[string]interface{}) (map[string]interface{}, error) {
	L := m.newSandboxedState()
	defer L.Close()

	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	L.SetContext(ctx)

	dataTable := createJSONTable(L, jsonObj)

	startTime := time.Now()

	// Load and execute the wrapped script (defines the function)
	if err := L.DoString(m.wrapped); err != nil {
		duration := time.Since(startTime).Seconds()
		metric.LuaExecutionTime("unknown", "json_modifier", duration)
		slog.Debug("error evaluating JSON script", "error", err)
		return jsonObj, err
	}

	// Call modify_json(data, ctx)
	fn := L.GetGlobal("modify_json")
	if fn == lua.LNil {
		duration := time.Since(startTime).Seconds()
		metric.LuaExecutionTime("unknown", "json_modifier", duration)
		slog.Debug("JSON script did not define modify_json function")
		return jsonObj, nil
	}

	ctxTable := L.NewTable()
	if err := L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, dataTable, ctxTable); err != nil {
		duration := time.Since(startTime).Seconds()
		metric.LuaExecutionTime("unknown", "json_modifier", duration)
		slog.Debug("error calling modify_json", "error", err)
		return jsonObj, err
	}

	duration := time.Since(startTime).Seconds()
	metric.LuaExecutionTime("unknown", "json_modifier", duration)

	if L.GetTop() == 0 {
		return jsonObj, nil
	}

	ret := L.Get(-1)
	L.Pop(1)

	modifications, err := extractJSONModifications(L, ret)
	if err != nil {
		slog.Debug("error extracting JSON modifications", "error", err)
		return jsonObj, err
	}

	modifiedJSON, err := applyJSONModifications(jsonObj, modifications)
	if err != nil {
		slog.Debug("error applying JSON modifications", "error", err)
		return jsonObj, err
	}

	return modifiedJSON, nil
}

// NewJSONModifier creates a new Lua JSON modifier for JSON objects.
//
// The script must return a table with modification instructions. Two patterns
// are supported:
//
// Function-based (preferred):
//
//	function modify_json(data, ctx)
//	  return {
//	    set_fields = {new_field = "value", updated_field = 123}
//	  }
//	end
//
// Bare return (backward compatible, auto-wrapped):
//
//	return {
//	  set_fields = {new_field = "value"}
//	}
//
// The return table supports the following optional keys:
//   - set_fields: table of field name to value (adds or replaces fields)
//   - delete_fields: array of field names to remove
//   - modified_json: complete replacement JSON object (overrides other operations)
func NewJSONModifier(script string) (JSONModifier, error) {
	return NewJSONModifierWithTimeout(script, DefaultTimeout)
}

// NewJSONModifierWithTimeout creates a new Lua JSON modifier with a custom timeout
func NewJSONModifierWithTimeout(script string, timeout time.Duration) (JSONModifier, error) {
	if script == "" {
		return nil, nil
	}

	// Wrap bare scripts into function modify_json(data, ctx) for consistency.
	// Scripts that already define the function are left as-is.
	wrapped := wrapJSONModifierScript(script)
	useFunc := isJSONModifierFunction(script)

	// Validate by compiling the wrapped script
	L := newSandboxedState()
	defer L.Close()

	if _, err := L.LoadString(wrapped); err != nil {
		return nil, err
	}

	return &jsonModifier{
		script:  script,
		wrapped: wrapped,
		timeout: timeout,
		useFunc: useFunc,
	}, nil
}

// newSandboxedState creates a new Lua state with security restrictions
func (m *jsonModifier) newSandboxedState() *lua.LState {
	return newSandboxedState()
}

// createJSONTable creates a Lua table with JSON data
func createJSONTable(L *lua.LState, jsonObj map[string]interface{}) *lua.LTable {
	jsonTable := L.NewTable()

	if jsonObj == nil {
		return jsonTable
	}

	// Convert Go map to Lua table
	for k, v := range jsonObj {
		jsonTable.RawSetString(k, convertGoToLua(L, v))
	}

	return jsonTable
}

// convertGoToLua converts Go values to Lua values
func convertGoToLua(L *lua.LState, value interface{}) lua.LValue {
	switch v := value.(type) {
	case nil:
		return lua.LNil
	case bool:
		return lua.LBool(v)
	case int:
		return lua.LNumber(v)
	case int64:
		return lua.LNumber(v)
	case float64:
		return lua.LNumber(v)
	case string:
		return lua.LString(v)
	case []interface{}:
		table := L.NewTable()
		for i, item := range v {
			table.RawSetInt(i+1, convertGoToLua(L, item))
		}
		return table
	case map[string]interface{}:
		table := L.NewTable()
		for k, v := range v {
			table.RawSetString(k, convertGoToLua(L, v))
		}
		return table
	default:
		// For unknown types, convert to string
		return lua.LString(fmt.Sprintf("%v", v))
	}
}

// convertLuaToGo converts Lua values to Go values
func convertLuaToGo(L *lua.LState, value lua.LValue) interface{} {
	switch v := value.(type) {
	case *lua.LNilType:
		return nil
	case lua.LBool:
		return bool(v)
	case lua.LNumber:
		return float64(v)
	case lua.LString:
		return string(v)
	case *lua.LTable:
		// Check if it's an array (consecutive integer keys starting from 1)
		isArray := true
		maxKey := 0
		v.ForEach(func(k, val lua.LValue) {
			if key, ok := k.(lua.LNumber); ok {
				if int(key) > maxKey {
					maxKey = int(key)
				}
			} else {
				isArray = false
			}
		})

		if isArray && maxKey > 0 {
			// Convert to slice
			result := make([]interface{}, maxKey)
			v.ForEach(func(k, val lua.LValue) {
				if key, ok := k.(lua.LNumber); ok {
					idx := int(key) - 1
					if idx >= 0 && idx < maxKey {
						result[idx] = convertLuaToGo(L, val)
					}
				}
			})
			return result
		} else {
			// Convert to map
			result := make(map[string]interface{})
			v.ForEach(func(k, val lua.LValue) {
				if key, ok := k.(lua.LString); ok {
					result[string(key)] = convertLuaToGo(L, val)
				}
			})
			return result
		}
	default:
		return fmt.Sprintf("%v", v)
	}
}

// extractJSONModifications extracts JSONModificationResult from the Lua table
func extractJSONModifications(L *lua.LState, value lua.LValue) (*JSONModificationResult, error) {
	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("%w: got %s", util.ErrExpectedTableResult, value.Type())
	}

	result := &JSONModificationResult{
		SetFields:    make(map[string]interface{}),
		DeleteFields: []string{},
	}

	// Extract set_fields
	if setFields := L.GetField(table, "set_fields"); setFields != lua.LNil {
		if tbl, ok := setFields.(*lua.LTable); ok {
			tbl.ForEach(func(k, v lua.LValue) {
				if kStr, ok := k.(lua.LString); ok {
					result.SetFields[string(kStr)] = convertLuaToGo(L, v)
				}
			})
		}
	}

	// Extract delete_fields
	if deleteFields := L.GetField(table, "delete_fields"); deleteFields != lua.LNil {
		if tbl, ok := deleteFields.(*lua.LTable); ok {
			tbl.ForEach(func(k, v lua.LValue) {
				if vStr, ok := v.(lua.LString); ok {
					result.DeleteFields = append(result.DeleteFields, string(vStr))
				}
			})
		}
	}

	// Extract modified_json (overrides other operations)
	if modifiedJSON := L.GetField(table, "modified_json"); modifiedJSON != lua.LNil {
		if tbl, ok := modifiedJSON.(*lua.LTable); ok {
			modifiedMap := make(map[string]interface{})
			tbl.ForEach(func(k, v lua.LValue) {
				if kStr, ok := k.(lua.LString); ok {
					modifiedMap[string(kStr)] = convertLuaToGo(L, v)
				}
			})
			result.ModifiedJSON = modifiedMap
		}
	} else if len(result.SetFields) == 0 && len(result.DeleteFields) == 0 {
		// If no modified_json, set_fields, or delete_fields, treat the entire returned table as modified_json
		// This allows scripts to return data directly: return {config_data = {...}}
		modifiedMap := make(map[string]interface{})
		table.ForEach(func(k, v lua.LValue) {
			if kStr, ok := k.(lua.LString); ok {
				modifiedMap[string(kStr)] = convertLuaToGo(L, v)
			}
		})
		if len(modifiedMap) > 0 {
			result.ModifiedJSON = modifiedMap
		}
	}

	return result, nil
}

// applyJSONModifications applies the modifications to the JSON object and returns a new object
func applyJSONModifications(jsonObj map[string]interface{}, mods *JSONModificationResult) (map[string]interface{}, error) {
	// If modified_json is provided, use it directly
	if mods.ModifiedJSON != nil {
		return mods.ModifiedJSON, nil
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

// ParseJSONModificationScript parses a Lua script and returns a JSONModifier
func ParseJSONModificationScript(script string) (JSONModifier, error) {
	return NewJSONModifier(script)
}

// ModifyJSONWithScript is a convenience function that creates a modifier and applies it to a JSON object
func ModifyJSONWithScript(jsonObj map[string]interface{}, script string) (map[string]interface{}, error) {
	modifier, err := NewJSONModifier(script)
	if err != nil {
		return jsonObj, fmt.Errorf("%w: %v", util.ErrJSONModifierCreationFailed, err)
	}
	return modifier.ModifyJSON(jsonObj)
}

// ModifyJSONString is a convenience function that works with JSON strings
func ModifyJSONString(jsonStr string, script string) (string, error) {
	// Parse the input JSON
	var jsonObj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonObj); err != nil {
		return jsonStr, fmt.Errorf("%w: %v", util.ErrJSONParseFailed, err)
	}

	// Apply modifications
	modifiedJSON, err := ModifyJSONWithScript(jsonObj, script)
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
