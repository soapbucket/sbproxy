// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// ErrNoResponseModifications is returned when a Lua script produces no modifications.
var ErrNoResponseModifications = errors.New("lua: no response modifications returned")

// ResponseModificationResult represents the modifications to be applied to a response.
type ResponseModificationResult struct {
	// SetHeaders contains headers to set (replaces existing values)
	SetHeaders map[string]string
	// AddHeaders contains headers to add (appends to existing values)
	AddHeaders map[string]string
	// DeleteHeaders contains header names to delete
	DeleteHeaders []string
	
	// Status modifications
	StatusCode int    // New status code to set (if not 0)
	StatusText string // Custom status text (overrides default for status code)
	
	// Body modifications
	Body              string // Simple body replacement (deprecated, use BodyReplace)
	BodyRemove        bool   // Remove body entirely
	BodyReplace       string // Replace body with string
	BodyReplaceJSON   string // Replace body with JSON (validates and sets Content-Type)
	BodyReplaceBase64 string // Replace body with base64-decoded content
}

// ResponseModifier modifies HTTP responses based on Lua scripts.
type ResponseModifier interface {
	// ModifyResponse evaluates the Lua script and applies the modifications to the response.
	// Returns any error that occurred.
	ModifyResponse(*http.Response) error
}

type responseModifier struct {
	script  string
	timeout time.Duration
}

// ModifyResponse evaluates the Lua script and applies modifications to the response
// The script must define a function: function modify_response(resp, ctx)
// that returns a table with modification instructions
func (m *responseModifier) ModifyResponse(resp *http.Response) error {
	L := m.newSandboxedState()
	defer L.Close()

	// Set up timeout context
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Measure Lua execution time
	startTime := time.Now()

	// Load the script
	if err := L.DoString(m.script); err != nil {
		duration := time.Since(startTime).Seconds()

		// Get origin from config context
		origin := "unknown"
		if resp != nil && resp.Request != nil {
			requestData := reqctx.GetRequestData(resp.Request.Context())
			if requestData != nil && requestData.Config != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
			// Fallback to hostname if config_id not available
			if origin == "unknown" && resp.Request.Host != "" {
				origin = resp.Request.Host
			}
		}

		// Record Lua execution time even on error
		metric.LuaExecutionTime(origin, "response_modifier", duration)

		slog.Debug("error loading response script", "url", resp.Request.URL, "error", err)
		return nil // No-op on error
	}

	// Get the modify_response function
	modifyFn := L.GetGlobal("modify_response")
	if modifyFn.Type() != lua.LTFunction {
		duration := time.Since(startTime).Seconds()

		// Get origin from config context
		origin := "unknown"
		if resp != nil && resp.Request != nil {
			requestData := reqctx.GetRequestData(resp.Request.Context())
			if requestData != nil && requestData.Config != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
			// Fallback to hostname if config_id not available
			if origin == "unknown" && resp.Request.Host != "" {
				origin = resp.Request.Host
			}
		}

		// Record Lua execution time
		metric.LuaExecutionTime(origin, "response_modifier", duration)

		slog.Debug("modify_response function not found", "url", resp.Request.URL)
		return nil // No-op on error
	}

	// Build request context
	req := resp.Request
	if req == nil {
		return nil
	}

	rc := NewRequestContext(req)
	rc.PopulateLuaState(L)
	L.SetGlobal("request", createRequestTable(L, req))
	L.SetGlobal("cookies", createCookiesTable(L, req))
	L.SetGlobal("params", createParamsTable(L, req))
	ctxTable := rc.BuildContextTable(L)
	ctxTable.RawSetString("ip", L.GetGlobal("ip"))

	// Add response fields to context
	if resp.StatusCode > 0 {
		ctxTable.RawSetString("response_status", lua.LNumber(resp.StatusCode))
	}

	// Add response headers to context
	respHeadersTable := L.NewTable()
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeadersTable.RawSetString(strings.ToLower(k), lua.LString(v[0]))
			respHeadersTable.RawSetString(k, lua.LString(v[0]))
		}
	}
	ctxTable.RawSetString("response_headers", respHeadersTable)

	// Build response table
	respTable := createResponseTable(L, resp)
	L.SetGlobal("response", respTable)

	// Call the modify_response function with resp and ctx tables
	L.Push(modifyFn)
	L.Push(respTable)
	L.Push(ctxTable)

	// Execute the function call
	if err := L.PCall(2, 1, nil); err != nil {
		duration := time.Since(startTime).Seconds()

		// Get origin from config context
		origin := "unknown"
		if resp != nil && resp.Request != nil {
			requestData := reqctx.GetRequestData(resp.Request.Context())
			if requestData != nil && requestData.Config != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
			// Fallback to hostname if config_id not available
			if origin == "unknown" && resp.Request.Host != "" {
				origin = resp.Request.Host
			}
		}

		// Record Lua execution time even on error
		metric.LuaExecutionTime(origin, "response_modifier", duration)

		slog.Debug("error calling modify_response", "url", resp.Request.URL, "error", err)
		return nil // No-op on error
	}

	duration := time.Since(startTime).Seconds()

	// Get origin from config context
	origin := "unknown"
	if resp != nil && resp.Request != nil {
		requestData := reqctx.GetRequestData(resp.Request.Context())
		if requestData != nil && requestData.Config != nil {
			if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
				origin = id
			}
		}
		// Fallback to hostname if config_id not available
		if origin == "unknown" && resp.Request.Host != "" {
			origin = resp.Request.Host
		}
	}

	// Record Lua execution time
	metric.LuaExecutionTime(origin, "response_modifier", duration)

	// Get the return value from the stack
	if L.GetTop() == 0 {
		slog.Debug("modify_response did not return a value", "url", resp.Request.URL)
		return nil // No-op
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Extract modifications from the returned table
	modifications, err := extractResponseModifications(L, ret)
	if err != nil {
		slog.Debug("error extracting response modifications", "url", resp.Request.URL, "error", err)
		return nil // No-op on error
	}

	// Apply modifications to the response
	err = applyResponseModifications(resp, modifications)
	if err != nil {
		slog.Debug("error applying response modifications", "url", resp.Request.URL, "error", err)
		return nil // No-op on error
	}

	return nil
}

// NewResponseModifier creates a new Lua response modifier for HTTP responses.
// The script must define a function: function modify_response(resp, ctx)
// that returns a table with modification instructions.
//
// The resp table has the following fields:
//   - status_code: number - HTTP status code
//   - status: string - HTTP status text
//   - headers: table[string]string - Response headers
//   - body: string - Response body content
//
// The ctx table includes:
//   - All request context data (request_ip, location, user_agent, session, etc.)
//   - response_status: number - HTTP status code
//   - response_headers: table[string]string - Response headers
//   - request: table (request info: method, path, host, headers, query)
//
// The function must return a table with the following optional keys:
//   - set_headers: table[string]string - Headers to set (replaces existing)
//   - add_headers: table[string]string - Headers to add (appends to existing)
//   - delete_headers: array of strings - Header names to delete
//   - status_code: number - New status code to set
//   - status_text: string - Custom status text
//   - body_remove: bool - Remove body entirely
//   - body_replace: string - Replace body with string
//   - body_replace_json: string - Replace body with JSON
//   - body_replace_base64: string - Replace body with base64-decoded content
//
// Example scripts:
//
//	function modify_response(resp, ctx)
//	  return {
//	    set_headers = {["X-Custom"] = "value"},
//	    status_code = 200
//	  }
//	end
//
//	function modify_response(resp, ctx)
//	  return {
//	    set_headers = {["X-Country"] = ctx.location.country_code},
//	    body_replace = resp.body .. " [modified]"
//	  }
//	end
func NewResponseModifier(script string) (ResponseModifier, error) {
	return NewResponseModifierWithTimeout(script, DefaultTimeout)
}

// NewResponseModifierWithTimeout creates a new Lua response modifier with a custom timeout
func NewResponseModifierWithTimeout(script string, timeout time.Duration) (ResponseModifier, error) {
	script = wrapResponseModifierScript(script)
	// Validate the script by running it in a test state
	L := newSandboxedState()
	defer L.Close()

	// Try to compile and check for modify_response function
	if err := L.DoString(script); err != nil {
		return nil, fmt.Errorf("lua: script compilation error: %w", err)
	}

	// Validate that modify_response function exists
	modifyFn := L.GetGlobal("modify_response")
	if modifyFn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("lua: missing required function 'modify_response' in response modifier script")
	}

	return &responseModifier{
		script:  script,
		timeout: timeout,
	}, nil
}

// newSandboxedState creates a new Lua state with security restrictions
func (m *responseModifier) newSandboxedState() *lua.LState {
	return newSandboxedState()
}


// createResponseTable creates a Lua table with response data
func createResponseTable(L *lua.LState, resp *http.Response) *lua.LTable {
	respTable := L.NewTable()

	if resp == nil {
		// Return empty table for validation
		respTable.RawSetString("status_code", lua.LNumber(0))
		respTable.RawSetString("status", lua.LString(""))
		respTable.RawSetString("headers", L.NewTable())
		respTable.RawSetString("body", lua.LString(""))
		return respTable
	}

	// Set status code and status
	respTable.RawSetString("status_code", lua.LNumber(resp.StatusCode))
	respTable.RawSetString("status", lua.LString(resp.Status))

	// Create headers table
	// Normalize headers to lowercase with hyphens converted to underscores for consistent access
	headers := L.NewTable()
	for k, v := range resp.Header {
		if len(v) > 0 {
			headerKey := strings.ToLower(k)
			headerKey = strings.ReplaceAll(headerKey, "-", "_")
			headers.RawSetString(headerKey, lua.LString(v[0]))
			headers.RawSetString(k, lua.LString(v[0]))
		}
	}
	respTable.RawSetString("headers", headers)

	// Read body content
	var bodyString string
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil {
			bodyString = string(bodyBytes)
			// Restore the body for later use
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}
	respTable.RawSetString("body", lua.LString(bodyString))

	return respTable
}

// extractResponseModifications extracts ResponseModificationResult from the Lua table
func extractResponseModifications(L *lua.LState, value lua.LValue) (*ResponseModificationResult, error) {
	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("lua: expected table result, got %s", value.Type())
	}

	result := &ResponseModificationResult{
		SetHeaders:    make(map[string]string),
		AddHeaders:    make(map[string]string),
		DeleteHeaders: []string{},
	}

	// Extract set_headers
	// Normalize header names to lowercase for consistency (http.Header is case-insensitive, but normalization ensures consistency)
	if setHeaders := L.GetField(table, "set_headers"); setHeaders != lua.LNil {
		if tbl, ok := setHeaders.(*lua.LTable); ok {
			tbl.ForEach(func(k, v lua.LValue) {
				if kStr, ok := k.(lua.LString); ok {
					if vStr, ok := v.(lua.LString); ok {
						result.SetHeaders[strings.ToLower(string(kStr))] = string(vStr)
					}
				}
			})
		}
	}

	// Extract add_headers
	if addHeaders := L.GetField(table, "add_headers"); addHeaders != lua.LNil {
		if tbl, ok := addHeaders.(*lua.LTable); ok {
			tbl.ForEach(func(k, v lua.LValue) {
				if kStr, ok := k.(lua.LString); ok {
					if vStr, ok := v.(lua.LString); ok {
						result.AddHeaders[strings.ToLower(string(kStr))] = string(vStr)
					}
				}
			})
		}
	}

	// Extract delete_headers
	if deleteHeaders := L.GetField(table, "delete_headers"); deleteHeaders != lua.LNil {
		if tbl, ok := deleteHeaders.(*lua.LTable); ok {
			tbl.ForEach(func(k, v lua.LValue) {
				if vStr, ok := v.(lua.LString); ok {
					result.DeleteHeaders = append(result.DeleteHeaders, strings.ToLower(string(vStr)))
				}
			})
		}
	}

	// Helper functions for extraction
	extractString := func(fieldName string) string {
		if val := L.GetField(table, fieldName); val != lua.LNil {
			if str, ok := val.(lua.LString); ok {
				return string(str)
			}
		}
		return ""
	}

	extractBool := func(fieldName string) bool {
		if val := L.GetField(table, fieldName); val != lua.LNil {
			if b, ok := val.(lua.LBool); ok {
				return bool(b)
			}
		}
		return false
	}

	// Extract status_code
	if statusCode := L.GetField(table, "status_code"); statusCode != lua.LNil {
		if statusNum, ok := statusCode.(lua.LNumber); ok {
			result.StatusCode = int(statusNum)
		}
	}

	// Extract status_text
	result.StatusText = extractString("status_text")

	// Extract body (deprecated, but still supported)
	result.Body = extractString("body")

	// Extract body modifications
	result.BodyRemove = extractBool("body_remove")
	result.BodyReplace = extractString("body_replace")
	result.BodyReplaceJSON = extractString("body_replace_json")
	result.BodyReplaceBase64 = extractString("body_replace_base64")

	return result, nil
}

// applyResponseModifications applies the modifications to the response
func applyResponseModifications(resp *http.Response, mods *ResponseModificationResult) error {
	// Ensure we have a proper header map
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}

	// Apply header modifications
	for _, headerName := range mods.DeleteHeaders {
		resp.Header.Del(headerName)
	}
	for k, v := range mods.SetHeaders {
		resp.Header.Set(k, v)
	}
	for k, v := range mods.AddHeaders {
		resp.Header.Add(k, v)
	}

	// Apply status code and text modifications
	if mods.StatusCode != 0 {
		resp.StatusCode = mods.StatusCode
		if mods.StatusText != "" {
			// Use custom status text
			resp.Status = fmt.Sprintf("%d %s", mods.StatusCode, mods.StatusText)
		} else {
			// Use default status text
			resp.Status = http.StatusText(mods.StatusCode)
			if resp.Status == "" {
				resp.Status = strconv.Itoa(mods.StatusCode)
			} else {
				resp.Status = fmt.Sprintf("%d %s", mods.StatusCode, resp.Status)
			}
		}
	} else if mods.StatusText != "" {
		// Only status text provided, keep existing status code
		resp.Status = fmt.Sprintf("%d %s", resp.StatusCode, mods.StatusText)
	}

	// Apply body modifications
	// Priority: BodyReplaceBase64 > BodyReplaceJSON > BodyReplace > Body (deprecated) > BodyRemove
	if mods.BodyReplaceBase64 != "" || mods.BodyReplaceJSON != "" || 
	   mods.BodyReplace != "" || mods.Body != "" || mods.BodyRemove {
		var bodyBytes []byte
		var err error

		if mods.BodyReplaceBase64 != "" {
			bodyBytes, err = base64.StdEncoding.DecodeString(mods.BodyReplaceBase64)
			if err != nil {
				return fmt.Errorf("failed to decode base64 body: %w", err)
			}
		} else if mods.BodyReplaceJSON != "" {
			// Validate JSON
			if !json.Valid([]byte(mods.BodyReplaceJSON)) {
				return fmt.Errorf("invalid JSON body")
			}
			bodyBytes = []byte(mods.BodyReplaceJSON)
			resp.Header.Set("Content-Type", "application/json")
		} else if mods.BodyReplace != "" {
			bodyBytes = []byte(mods.BodyReplace)
		} else if mods.Body != "" {
			// Support deprecated 'body' field
			bodyBytes = []byte(mods.Body)
		} else if mods.BodyRemove {
			bodyBytes = []byte{}
		}

		// Update response body
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))

		if len(bodyBytes) == 0 {
			resp.Header.Del("Content-Length")
		} else {
			resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		}
	}

	return nil
}

// ApplyResponseModifications is a helper function that applies ResponseModificationResult to a response
func ApplyResponseModifications(resp *http.Response, mods *ResponseModificationResult) error {
	return applyResponseModifications(resp, mods)
}

// ParseResponseModificationScript parses a Lua script and returns a ResponseModifier
func ParseResponseModificationScript(script string) (ResponseModifier, error) {
	return NewResponseModifier(script)
}

// ModifyResponseWithScript is a convenience function that creates a modifier and applies it to a response
func ModifyResponseWithScript(resp *http.Response, script string) error {
	modifier, err := NewResponseModifier(script)
	if err != nil {
		return fmt.Errorf("failed to create response modifier: %w", err)
	}
	return modifier.ModifyResponse(resp)
}
