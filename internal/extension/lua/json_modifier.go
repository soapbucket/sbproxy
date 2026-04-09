// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"github.com/soapbucket/sbproxy/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
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
	timeout time.Duration
}

// ModifyJSON evaluates the Lua script and applies modifications to the JSON object
func (m *jsonModifier) ModifyJSON(jsonObj map[string]interface{}) (map[string]interface{}, error) {
	L := m.newSandboxedState()
	defer L.Close()

	// Set up timeout context
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Populate JSON data
	m.setJSONVar(L, jsonObj)

	// Measure Lua execution time
	startTime := time.Now()
	
	// Execute the script
	if err := L.DoString(m.script); err != nil {
		duration := time.Since(startTime).Seconds()
		
		// Record Lua execution time (origin unknown for JSON modifications)
		metric.LuaExecutionTime("unknown", "json_modifier", duration)
		
		slog.Debug("error evaluating JSON script", "error", err)
		return jsonObj, err
	}
	
	duration := time.Since(startTime).Seconds()
	
	// Record Lua execution time (origin unknown for JSON modifications)
	metric.LuaExecutionTime("unknown", "json_modifier", duration)

	// Get the return value from the stack
	if L.GetTop() == 0 {
		slog.Debug("JSON script did not return a value")
		return jsonObj, nil
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Extract modifications from the returned table
	modifications, err := extractJSONModifications(L, ret)
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

// NewJSONModifier creates a new Lua JSON modifier for JSON objects.
// The script must return a table with modification instructions.
//
// The script has access to:
//   - json: The input JSON object as a table
//
// The script must return a table with the following optional keys:
//   - set_fields: table[string]interface{} - Fields to set (replaces existing)
//   - delete_fields: array of strings - Field names to delete
//   - modified_json: table[string]interface{} - Complete modified JSON object (overrides other operations)
//
// Example scripts:
//
//	return {
//	  set_fields = {new_field = "value", updated_field = 123}
//	}
//
//	return {
//	  delete_fields = {"old_field", "sensitive_data"}
//	}
//
//	return {
//	  set_fields = {status = "modified"},
//	  delete_fields = {"internal_id"}
//	}
//
//	return {
//	  modified_json = {
//	    id = json.id,
//	    name = json.name,
//	    status = "processed"
//	  }
//	}
func NewJSONModifier(script string) (JSONModifier, error) {
	return NewJSONModifierWithTimeout(script, DefaultTimeout)
}

// NewJSONModifierWithTimeout creates a new Lua JSON modifier with a custom timeout
func NewJSONModifierWithTimeout(script string, timeout time.Duration) (JSONModifier, error) {
	// Check for empty script
	if script == "" {
		return nil, nil
	}

	// Validate the script by running it in a test state
	L := newSandboxedState()
	defer L.Close()

	// Create dummy variables for validation
	L.SetGlobal("json", L.NewTable())

	// Try to compile the script
	if _, err := L.LoadString(script); err != nil {
		return nil, err
	}

	return &jsonModifier{
		script:  script,
		timeout: timeout,
	}, nil
}

// newSandboxedState creates a new Lua state with security restrictions
func (m *jsonModifier) newSandboxedState() *lua.LState {
	return newSandboxedState()
}

// setJSONVar populates the Lua state with JSON data
func (m *jsonModifier) setJSONVar(L *lua.LState, jsonObj map[string]interface{}) {
	L.SetGlobal("json", createJSONTable(L, jsonObj))
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
