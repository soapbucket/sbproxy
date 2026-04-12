// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	lua "github.com/yuin/gopher-lua"
)

// JSONTransformError represents an error during JSON transformation.
type JSONTransformError struct {
	Type    JSONTransformErrorType
	Message string
	Cause   error
	Script  string // First 100 chars of script for context
	Details map[string]interface{}
}

// JSONTransformErrorType categorizes JSON transformation errors.
type JSONTransformErrorType int

const (
	// ErrorTypeScriptEmpty indicates the script was empty
	ErrorTypeScriptEmpty JSONTransformErrorType = iota
	// ErrorTypeScriptCompilation indicates a Lua compilation error
	ErrorTypeScriptCompilation
	// ErrorTypeScriptMissingFunction indicates modify_json function is missing
	ErrorTypeScriptMissingFunction
	// ErrorTypeScriptExecution indicates a runtime error in the script
	ErrorTypeScriptExecution
	// ErrorTypeScriptTimeout indicates the script execution timed out
	ErrorTypeScriptTimeout
	// ErrorTypeJSONParse indicates JSON parsing failed
	ErrorTypeJSONParse
	// ErrorTypeJSONMarshal indicates JSON marshaling failed
	ErrorTypeJSONMarshal
	// ErrorTypeBodyRead indicates response body read failed
	ErrorTypeBodyRead
	// ErrorTypeNoReturn indicates the function didn't return a value
	ErrorTypeNoReturn
)

// String returns a human-readable representation of the JSONTransformErrorType.
func (t JSONTransformErrorType) String() string {
	switch t {
	case ErrorTypeScriptEmpty:
		return "script_empty"
	case ErrorTypeScriptCompilation:
		return "script_compilation"
	case ErrorTypeScriptMissingFunction:
		return "script_missing_function"
	case ErrorTypeScriptExecution:
		return "script_execution"
	case ErrorTypeScriptTimeout:
		return "script_timeout"
	case ErrorTypeJSONParse:
		return "json_parse"
	case ErrorTypeJSONMarshal:
		return "json_marshal"
	case ErrorTypeBodyRead:
		return "body_read"
	case ErrorTypeNoReturn:
		return "no_return"
	default:
		return "unknown"
	}
}

// Error performs the error operation on the JSONTransformError.
func (e *JSONTransformError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("lua_json %s: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("lua_json %s: %s", e.Type, e.Message)
}

// Unwrap performs the unwrap operation on the JSONTransformError.
func (e *JSONTransformError) Unwrap() error {
	return e.Cause
}

// IsTimeout returns true if this error was caused by a timeout.
func (e *JSONTransformError) IsTimeout() bool {
	if e.Type == ErrorTypeScriptTimeout {
		return true
	}
	if e.Cause != nil {
		// Check if the cause contains context deadline exceeded
		if errors.Is(e.Cause, context.DeadlineExceeded) {
			return true
		}
		// Also check the error message for "context deadline exceeded"
		// as the Lua VM wraps the error
		if strings.Contains(e.Cause.Error(), "context deadline exceeded") {
			return true
		}
	}
	return false
}

// IsRetryable returns true if the operation might succeed on retry.
func (e *JSONTransformError) IsRetryable() bool {
	return e.Type == ErrorTypeScriptTimeout
}

// newJSONTransformError creates a new JSONTransformError with optional script snippet.
func newJSONTransformError(errType JSONTransformErrorType, message string, cause error, script string) *JSONTransformError {
	scriptSnippet := ""
	if script != "" {
		if len(script) > 100 {
			scriptSnippet = script[:100] + "..."
		} else {
			scriptSnippet = script
		}
	}
	return &JSONTransformError{
		Type:    errType,
		Message: message,
		Cause:   cause,
		Script:  scriptSnippet,
	}
}

// JSONTransformer transforms JSON response bodies using Lua scripts.
// The script must define a function: modify_json(data, ctx)
// that receives the parsed JSON as a Lua table (and optional context) and returns the transformed data.
type JSONTransformer interface {
	// TransformResponse transforms the JSON body of an HTTP response.
	// The response body is parsed as JSON, passed to the Lua modify_json function,
	// and the result is marshaled back to JSON as the new response body.
	TransformResponse(*http.Response) error

	// TransformData transforms arbitrary data using the Lua script.
	// Returns the transformed data or an error.
	TransformData(data interface{}) (interface{}, error)

	// TransformRequestData transforms data with access to request context variables.
	// The Lua script can access request.path, request.method, headers, cookies,
	// location, session, config, variables, etc.
	TransformRequestData(data interface{}, req *http.Request) (interface{}, error)
}

type jsonTransformer struct {
	script  string
	timeout time.Duration
}

// NewJSONTransformer creates a new Lua JSON transformer with the default timeout.
// The script must define a function modify_json(data, ctx) that receives the parsed
// JSON body as a Lua table and context data, and returns the transformed data.
//
// The ctx table includes all available context: request_ip, location, user_agent,
// fingerprint, session, config, request_data, variables, secrets, env, features,
// server, and request information.
//
// Example script:
//
//	function modify_json(data, ctx)
//	  -- Convert country codes based on location
//	  local country_map = {GERMANY = 'DE', FRANCE = 'FR'}
//	  if data.country and country_map[data.country] then
//	    data.country = country_map[data.country]
//	  end
//	  -- Add geographic data
//	  if ctx.location then
//	    data.request_country = ctx.location.country_code
//	  end
//	  return data
//	end
func NewJSONTransformer(script string) (JSONTransformer, error) {
	return NewJSONTransformerWithTimeout(script, DefaultTimeout)
}

// NewJSONTransformerWithTimeout creates a new Lua JSON transformer with a custom timeout.
func NewJSONTransformerWithTimeout(script string, timeout time.Duration) (JSONTransformer, error) {
	if script == "" {
		return nil, newJSONTransformError(
			ErrorTypeScriptEmpty,
			"script cannot be empty",
			nil,
			"",
		)
	}

	// Trim whitespace and check again
	script = strings.TrimSpace(script)
	if script == "" {
		return nil, newJSONTransformError(
			ErrorTypeScriptEmpty,
			"script cannot be empty or whitespace only",
			nil,
			"",
		)
	}

	// Validate the script compiles and defines modify_json function
	L := newSandboxedState()
	defer L.Close()

	// Execute the script to define functions
	if err := L.DoString(script); err != nil {
		return nil, newJSONTransformError(
			ErrorTypeScriptCompilation,
			"failed to compile Lua script",
			err,
			script,
		)
	}

	// Check that modify_json function exists
	fn := L.GetGlobal("modify_json")
	if fn.Type() != lua.LTFunction {
		return nil, newJSONTransformError(
			ErrorTypeScriptMissingFunction,
			"script must define function modify_json(data, ctx)",
			nil,
			script,
		)
	}

	return &jsonTransformer{
		script:  script,
		timeout: timeout,
	}, nil
}

// TransformResponse transforms the JSON body of an HTTP response using the Lua script.
func (t *jsonTransformer) TransformResponse(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return newJSONTransformError(
			ErrorTypeBodyRead,
			"failed to read response body",
			err,
			t.script,
		)
	}

	// Handle empty body - restore and skip
	if len(bodyBytes) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil
	}

	// Parse JSON - support both objects and arrays
	var jsonData interface{}
	if err := json.Unmarshal(bodyBytes, &jsonData); err != nil {
		// Not valid JSON, restore body and skip transformation
		slog.Debug("lua_json: body is not valid JSON, skipping transformation",
			"error", err,
			"content_type", resp.Header.Get("Content-Type"))
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil // Not an error - just skip non-JSON content
	}

	// Execute Lua transformation
	transformedData, err := t.executeTransform(jsonData, resp)
	if err != nil {
		// On error, restore original body and return the error
		slog.Error("lua_json: transformation failed, using original body",
			"error", err,
			"error_type", getErrorType(err))
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return err
	}

	// Marshal transformed data back to JSON
	transformedBytes, err := json.Marshal(transformedData)
	if err != nil {
		slog.Error("lua_json: failed to marshal transformed data",
			"error", err)
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return newJSONTransformError(
			ErrorTypeJSONMarshal,
			"failed to marshal transformed data to JSON",
			err,
			t.script,
		)
	}

	// Update response with transformed body
	resp.Body = io.NopCloser(bytes.NewReader(transformedBytes))
	resp.ContentLength = int64(len(transformedBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(transformedBytes)))
	resp.Header.Set("Content-Type", "application/json")

	slog.Debug("lua_json: transformation successful",
		"original_size", len(bodyBytes),
		"transformed_size", len(transformedBytes))

	return nil
}

// TransformData transforms arbitrary data using the Lua script without HTTP context.
// This is useful for transforming data outside of HTTP response handling.
func (t *jsonTransformer) TransformData(data interface{}) (interface{}, error) {
	return t.executeTransform(data, nil)
}

// TransformRequestData transforms data with access to request context variables.
// The Lua script can access request.path, request.method, headers, cookies, etc.
func (t *jsonTransformer) TransformRequestData(data interface{}, req *http.Request) (interface{}, error) {
	L := newSandboxedState()
	defer L.Close()

	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Populate context from request directly
	if req != nil {
		L.SetGlobal("request", createRequestTable(L, req))
		L.SetGlobal("cookies", createCookiesTable(L, req))
		L.SetGlobal("params", createParamsTable(L, req))
		rc := NewRequestContext(req)
		rc.PopulateLuaState(L)
	}

	startTime := time.Now()
	origin := "unknown"
	if req != nil {
		requestData := reqctx.GetRequestData(req.Context())
		if requestData != nil && requestData.Config != nil {
			if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
				origin = id
			}
		}
		if origin == "unknown" && req.Host != "" {
			origin = req.Host
		}
	}

	recordAndError := func(errType JSONTransformErrorType, message string, cause error) *JSONTransformError {
		duration := time.Since(startTime).Seconds()
		metric.LuaExecutionTime(origin, "json_transformer_request", duration)
		if errors.Is(cause, context.DeadlineExceeded) {
			errType = ErrorTypeScriptTimeout
			message = fmt.Sprintf("script execution timed out after %v", t.timeout)
		}
		return newJSONTransformError(errType, message, cause, t.script)
	}

	if err := L.DoString(t.script); err != nil {
		return data, recordAndError(ErrorTypeScriptExecution, "failed to execute script", err)
	}

	fn := L.GetGlobal("modify_json")
	if fn.Type() != lua.LTFunction {
		return data, recordAndError(ErrorTypeScriptMissingFunction, "modify_json function not found", nil)
	}

	luaData := convertGoToLua(L, data)
	L.Push(fn)
	L.Push(luaData)
	if err := L.PCall(1, 1, nil); err != nil {
		return data, recordAndError(ErrorTypeScriptExecution, "modify_json execution failed", err)
	}

	duration := time.Since(startTime).Seconds()
	metric.LuaExecutionTime(origin, "json_transformer_request", duration)

	if L.GetTop() == 0 {
		return data, newJSONTransformError(ErrorTypeNoReturn, "modify_json did not return a value", nil, t.script)
	}

	result := L.Get(-1)
	L.Pop(1)

	if result == lua.LNil {
		slog.Debug("lua_json: modify_json returned nil, using original data")
		return data, nil
	}

	return convertLuaToGo(L, result), nil
}

// getErrorType extracts the error type string from an error if it's a JSONTransformError.
func getErrorType(err error) string {
	var transformErr *JSONTransformError
	if errors.As(err, &transformErr) {
		return transformErr.Type.String()
	}
	return "unknown"
}

// executeTransform executes the Lua modify_json function on the given data.
func (t *jsonTransformer) executeTransform(data interface{}, resp *http.Response) (interface{}, error) {
	L := newSandboxedState()
	defer L.Close()

	// Set up timeout context
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Populate context variables for the script to access
	if resp != nil && resp.Request != nil {
		L.SetGlobal("request", createRequestTable(L, resp.Request))
		L.SetGlobal("cookies", createCookiesTable(L, resp.Request))
		L.SetGlobal("params", createParamsTable(L, resp.Request))

		// Populate additional context (fingerprint, location, session, etc.)
		rc := NewRequestContext(resp.Request)
		rc.PopulateLuaState(L)
	}

	// Track execution time
	startTime := time.Now()
	origin := t.getOrigin(resp)

	// Helper to record metrics and create error
	recordAndError := func(errType JSONTransformErrorType, message string, cause error) *JSONTransformError {
		duration := time.Since(startTime).Seconds()
		metric.LuaExecutionTime(origin, "json_transformer", duration)

		// Check if this was a timeout
		if errors.Is(cause, context.DeadlineExceeded) {
			errType = ErrorTypeScriptTimeout
			message = fmt.Sprintf("script execution timed out after %v", t.timeout)
		}

		return newJSONTransformError(errType, message, cause, t.script)
	}

	// Execute the script (this defines the modify_json function)
	if err := L.DoString(t.script); err != nil {
		return data, recordAndError(
			ErrorTypeScriptExecution,
			"failed to execute script",
			err,
		)
	}

	// Get the modify_json function
	fn := L.GetGlobal("modify_json")
	if fn.Type() != lua.LTFunction {
		return data, recordAndError(
			ErrorTypeScriptMissingFunction,
			"modify_json function not found after script execution",
			nil,
		)
	}

	// Convert Go data to Lua value
	luaData := convertGoToLua(L, data)

	// Build context table for the script
	ctxTable := L.NewTable()
	if resp != nil && resp.Request != nil {
		rc := NewRequestContext(resp.Request)
		ctxTable = rc.BuildContextTable(L)

		// Add response-phase fields if we have a response
		if resp.StatusCode > 0 {
			ctxTable.RawSetString("response_status", lua.LNumber(resp.StatusCode))
		}
		respHeadersTable := L.NewTable()
		for k, v := range resp.Header {
			if len(v) > 0 {
				respHeadersTable.RawSetString(strings.ToLower(k), lua.LString(v[0]))
			}
		}
		ctxTable.RawSetString("response_headers", respHeadersTable)
	}

	// Call modify_json(data, ctx)
	L.Push(fn)
	L.Push(luaData)
	L.Push(ctxTable)
	if err := L.PCall(2, 1, nil); err != nil {
		return data, recordAndError(
			ErrorTypeScriptExecution,
			"modify_json function execution failed",
			err,
		)
	}

	// Record execution time
	duration := time.Since(startTime).Seconds()
	metric.LuaExecutionTime(origin, "json_transformer", duration)

	// Get result from stack
	if L.GetTop() == 0 {
		return data, newJSONTransformError(
			ErrorTypeNoReturn,
			"modify_json did not return a value",
			nil,
			t.script,
		)
	}

	result := L.Get(-1)
	L.Pop(1)

	// Handle nil return - return original data unchanged
	if result == lua.LNil {
		slog.Debug("lua_json: modify_json returned nil, using original data")
		return data, nil
	}

	// Convert Lua result back to Go
	return convertLuaToGo(L, result), nil
}

// getOrigin extracts the origin identifier for metrics from the response.
func (t *jsonTransformer) getOrigin(resp *http.Response) string {
	if resp == nil || resp.Request == nil {
		return "unknown"
	}

	// Try to get origin from request data/config
	requestData := reqctx.GetRequestData(resp.Request.Context())
	if requestData != nil && requestData.Config != nil {
		if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
			return id
		}
	}

	// Fallback to hostname
	if resp.Request.Host != "" {
		return resp.Request.Host
	}

	return "unknown"
}
