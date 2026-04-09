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
	"net/url"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// ErrNoModifications is returned when a Lua script produces no modifications.
var ErrNoModifications = errors.New("lua: no modifications returned")

// ModificationResult represents the modifications to be applied to a request.
type ModificationResult struct {
	// SetHeaders contains headers to set (replaces existing values)
	SetHeaders map[string]string
	// AddHeaders contains headers to add (appends to existing values)
	AddHeaders map[string]string
	// DeleteHeaders contains header names to delete
	DeleteHeaders []string
	
	// URL modifications
	Scheme   string // URL scheme (http, https)
	Host     string // URL host (including port if needed)
	Path     string // Full path replacement
	Fragment string // URL fragment
	
	// Path modifications (applied if Path is empty)
	PathPrefix  string // Prefix to add to path
	PathSuffix  string // Suffix to add to path
	PathReplace map[string]string // Replace old substring with new (map of old->new)
	
	// Method is the new HTTP method to set (if not empty)
	Method string
	
	// Query parameter modifications
	SetQuery    map[string]string // Query params to set (overwrites)
	AddQuery    map[string]string // Query params to add (appends)
	DeleteQuery []string          // Query param names to delete
	
	// Form parameter modifications
	SetForm    map[string]string // Form params to set (overwrites)
	AddForm    map[string]string // Form params to add (appends)
	DeleteForm []string          // Form param names to delete
	
	// Body modifications
	BodyRemove        bool   // Remove body entirely
	BodyReplace       string // Replace body with string
	BodyReplaceJSON   string // Replace body with JSON (validates and sets Content-Type)
	BodyReplaceBase64 string // Replace body with base64-decoded content
}

// Modifier modifies HTTP requests based on Lua scripts.
type Modifier interface {
	// Modify evaluates the Lua script and applies the modifications to the request.
	// Returns the modified request and any error that occurred.
	Modify(*http.Request) (*http.Request, error)
}

type modifier struct {
	script  string
	timeout time.Duration
}

// Modify evaluates the Lua script and applies modifications to the request
// The script must define a function: function modify_request(req, ctx)
// that returns a table with modification instructions
func (m *modifier) Modify(req *http.Request) (*http.Request, error) {
	L := m.newSandboxedState()
	defer L.Close()

	// Set up timeout context derived from the request context so that
	// client disconnects and server shutdown cancel Lua execution.
	reqCtx := req.Context()
	ctx, cancel := context.WithTimeout(reqCtx, m.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Measure Lua execution time
	startTime := time.Now()

	// Load the script (compile it)
	if err := L.DoString(m.script); err != nil {
		duration := time.Since(startTime).Seconds()

		// Get origin from config context
		origin := "unknown"
		if req != nil {
			requestData := reqctx.GetRequestData(req.Context())
			if requestData != nil && requestData.Config != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
			// Fallback to hostname if config_id not available
			if origin == "unknown" && req.Host != "" {
				origin = req.Host
			}
		}

		// Record Lua execution time even on error
		metric.LuaExecutionTime(origin, "modifier", duration)

		slog.Debug("error loading script", "url", req.URL, "error", err)
		return req, err
	}

	// Get the modify_request function
	modifyFn := L.GetGlobal("modify_request")
	if modifyFn.Type() != lua.LTFunction {
		duration := time.Since(startTime).Seconds()

		// Get origin from config context
		origin := "unknown"
		if req != nil {
			requestData := reqctx.GetRequestData(req.Context())
			if requestData != nil && requestData.Config != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
			// Fallback to hostname if config_id not available
			if origin == "unknown" && req.Host != "" {
				origin = req.Host
			}
		}

		// Record Lua execution time
		metric.LuaExecutionTime(origin, "modifier", duration)

		slog.Debug("modify_request function not found", "url", req.URL)
		return req, nil // No-op on error
	}

	// Build request context and tables
	rc := NewRequestContext(req)
	reqTable := createRequestTable(L, req)
	rc.PopulateLuaState(L)
	L.SetGlobal("request", reqTable)
	L.SetGlobal("cookies", createCookiesTable(L, req))
	L.SetGlobal("params", createParamsTable(L, req))
	ctxTable := rc.BuildContextTable(L)
	ctxTable.RawSetString("ip", L.GetGlobal("ip"))

	// Call the modify_request function with req and ctx tables
	L.Push(modifyFn)
	L.Push(reqTable)
	L.Push(ctxTable)

	// Execute the function call
	if err := L.PCall(2, 1, nil); err != nil {
		duration := time.Since(startTime).Seconds()

		// Get origin from config context
		origin := "unknown"
		if req != nil {
			requestData := reqctx.GetRequestData(req.Context())
			if requestData != nil && requestData.Config != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
			// Fallback to hostname if config_id not available
			if origin == "unknown" && req.Host != "" {
				origin = req.Host
			}
		}

		// Record Lua execution time even on error
		metric.LuaExecutionTime(origin, "modifier", duration)

		slog.Debug("error calling modify_request", "url", req.URL, "error", err)
		return req, nil // No-op on error
	}

	duration := time.Since(startTime).Seconds()

	// Get origin from config context
	origin := "unknown"
	if req != nil {
		requestData := reqctx.GetRequestData(req.Context())
		if requestData != nil && requestData.Config != nil {
			if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
				origin = id
			}
		}
		// Fallback to hostname if config_id not available
		if origin == "unknown" && req.Host != "" {
			origin = req.Host
		}
	}

	// Record Lua execution time
	metric.LuaExecutionTime(origin, "modifier", duration)

	// Get the return value from the stack
	if L.GetTop() == 0 {
		slog.Debug("modify_request did not return a value", "url", req.URL)
		return req, nil // No-op: no modifications
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Extract modifications from the returned table
	modifications, err := extractModifications(L, ret)
	if err != nil {
		slog.Debug("error extracting modifications", "url", req.URL, "error", err)
		return req, nil // No-op on error
	}

	// Apply modifications to the request
	modifiedReq, err := applyModifications(req, modifications)
	if err != nil {
		slog.Debug("error applying modifications", "url", req.URL, "error", err)
		return req, nil // No-op on error
	}

	return modifiedReq, nil
}

// NewModifier creates a new Lua modifier for HTTP requests.
// The script must define a function: function modify_request(req, ctx)
// that returns a table with modification instructions.
//
// The req table has the following fields:
//   - method: string - HTTP method
//   - path: string - Request path
//   - host: string - Request host
//   - headers: table with lowercase keys
//   - query: string (URL-encoded query string)
//   - data: table - RequestData.Data
//   - id: string - request ID
//   - size: number - content length
//
// The ctx table (ScriptContext) has all available context data.
//
// The function must return a table with the following optional keys:
//   - set_headers: table[string]string - Headers to set (replaces existing)
//   - add_headers: table[string]string - Headers to add (appends to existing)
//   - delete_headers: array of strings - Header names to delete
//   - scheme: string - URL scheme (http, https)
//   - host: string - URL host (including port if needed)
//   - path: string - Full path replacement
//   - path_prefix: string - Prefix to add to path
//   - path_suffix: string - Suffix to add to path
//   - path_replace: table[string]string - Replace old substring with new
//   - method: string - New HTTP method to set
//   - set_query: table[string]string - Query params to set (overwrites)
//   - add_query: table[string]string - Query params to add (appends)
//   - delete_query: array of strings - Query parameter names to delete
//   - set_form: table[string]string - Form params to set (overwrites)
//   - add_form: table[string]string - Form params to add (appends)
//   - delete_form: array of strings - Form parameter names to delete
//   - body_remove: bool - Remove body entirely
//   - body_replace: string - Replace body with string
//   - body_replace_json: string - Replace body with JSON
//   - body_replace_base64: string - Replace body with base64-decoded content
//
// Example scripts:
//
//	function modify_request(req, ctx)
//	  return {
//	    set_headers = {["X-Custom"] = "value"},
//	    path = "/new/path"
//	  }
//	end
//
//	function modify_request(req, ctx)
//	  return {
//	    add_headers = {["X-Country"] = ctx.location.country_code},
//	    add_query = {source = "proxy"}
//	  }
//	end
//
//	function modify_request(req, ctx)
//	  return {
//	    set_headers = {["X-Browser"] = ctx.user_agent.family},
//	    delete_headers = {"X-Old-Header"}
//	  }
//	end
func NewModifier(script string) (Modifier, error) {
	return NewModifierWithTimeout(script, DefaultTimeout)
}

// NewModifierWithTimeout creates a new Lua modifier with a custom timeout
func NewModifierWithTimeout(script string, timeout time.Duration) (Modifier, error) {
	script = wrapModifierScript(script)
	// Validate the script by running it in a test state
	L := newSandboxedState()
	defer L.Close()

	// Try to compile and check for modify_request function
	if err := L.DoString(script); err != nil {
		return nil, fmt.Errorf("lua: script compilation error: %w", err)
	}

	// Validate that modify_request function exists
	modifyFn := L.GetGlobal("modify_request")
	if modifyFn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("lua: missing required function 'modify_request' in modifier script")
	}

	return &modifier{
		script:  script,
		timeout: timeout,
	}, nil
}

// newSandboxedState creates a new Lua state with security restrictions
func (m *modifier) newSandboxedState() *lua.LState {
	return newSandboxedState()
}


// extractModifications extracts ModificationResult from the Lua table
func extractModifications(L *lua.LState, value lua.LValue) (*ModificationResult, error) {
	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("lua: expected table result, got %s", value.Type())
	}

	result := &ModificationResult{
		SetHeaders:  make(map[string]string),
		AddHeaders:  make(map[string]string),
		DeleteHeaders: []string{},
		PathReplace: make(map[string]string),
		SetQuery:    make(map[string]string),
		AddQuery:    make(map[string]string),
		DeleteQuery: []string{},
		SetForm:     make(map[string]string),
		AddForm:     make(map[string]string),
		DeleteForm:  []string{},
	}

	// Helper function to extract string from table
	extractString := func(fieldName string) string {
		if val := L.GetField(table, fieldName); val != lua.LNil {
			if str, ok := val.(lua.LString); ok {
				return string(str)
			}
		}
		return ""
	}

	// Helper function to extract bool from table
	extractBool := func(fieldName string) bool {
		if val := L.GetField(table, fieldName); val != lua.LNil {
			if b, ok := val.(lua.LBool); ok {
				return bool(b)
			}
		}
		return false
	}

	// Helper function to extract string map from table
	extractStringMap := func(fieldName string) map[string]string {
		m := make(map[string]string)
		if val := L.GetField(table, fieldName); val != lua.LNil {
			if tbl, ok := val.(*lua.LTable); ok {
				tbl.ForEach(func(k, v lua.LValue) {
					if kStr, ok := k.(lua.LString); ok {
						if vStr, ok := v.(lua.LString); ok {
							m[string(kStr)] = string(vStr)
						}
					}
				})
			}
		}
		return m
	}

	// Helper function to extract string array from table
	extractStringArray := func(fieldName string) []string {
		arr := []string{}
		if val := L.GetField(table, fieldName); val != lua.LNil {
			if tbl, ok := val.(*lua.LTable); ok {
				tbl.ForEach(func(k, v lua.LValue) {
					if vStr, ok := v.(lua.LString); ok {
						arr = append(arr, string(vStr))
					}
				})
			}
		}
		return arr
	}

	// Extract headers
	// Normalize header names to lowercase for consistency (http.Header is case-insensitive, but normalization ensures consistency)
	result.SetHeaders = normalizeHeaderMap(extractStringMap("set_headers"))
	result.AddHeaders = normalizeHeaderMap(extractStringMap("add_headers"))
	result.DeleteHeaders = normalizeHeaderSlice(extractStringArray("delete_headers"))

	// Extract URL modifications
	result.Scheme = extractString("scheme")
	result.Host = extractString("host")
	result.Path = extractString("path")
	result.Fragment = extractString("fragment")

	// Extract path modifications
	result.PathPrefix = extractString("path_prefix")
	result.PathSuffix = extractString("path_suffix")
	result.PathReplace = extractStringMap("path_replace")

	// Extract method
	result.Method = extractString("method")

	// Extract query modifications
	result.SetQuery = extractStringMap("set_query")
	result.AddQuery = extractStringMap("add_query")
	result.DeleteQuery = extractStringArray("delete_query")

	// Extract form modifications
	result.SetForm = extractStringMap("set_form")
	result.AddForm = extractStringMap("add_form")
	result.DeleteForm = extractStringArray("delete_form")

	// Extract body modifications
	result.BodyRemove = extractBool("body_remove")
	result.BodyReplace = extractString("body_replace")
	result.BodyReplaceJSON = extractString("body_replace_json")
	result.BodyReplaceBase64 = extractString("body_replace_base64")

	return result, nil
}

// applyModifications applies the modifications to the request and returns a new request
func applyModifications(req *http.Request, mods *ModificationResult) (*http.Request, error) {
	// Clone the request to avoid modifying the original
	modifiedReq := req.Clone(req.Context())

	// Ensure we have a proper header map
	if modifiedReq.Header == nil {
		modifiedReq.Header = make(http.Header)
	}

	// Apply URL scheme modification
	if mods.Scheme != "" {
		modifiedReq.URL.Scheme = mods.Scheme
	}

	// Apply URL host modification
	if mods.Host != "" {
		modifiedReq.URL.Host = mods.Host
		modifiedReq.Host = mods.Host
	}

	// Apply path modifications
	if mods.Path != "" {
		// Full path replacement
		modifiedReq.URL.Path = mods.Path
	} else {
		// Apply path transformations if no full replacement
		currentPath := modifiedReq.URL.Path
		
		// Apply path replace operations
		for old, new := range mods.PathReplace {
			if old != "" {
				currentPath = strings.ReplaceAll(currentPath, old, new)
			}
		}
		
		// Apply prefix
		if mods.PathPrefix != "" {
			currentPath = mods.PathPrefix + currentPath
		}
		
		// Apply suffix
		if mods.PathSuffix != "" {
			currentPath = currentPath + mods.PathSuffix
		}
		
		modifiedReq.URL.Path = currentPath
	}

	// Apply URL fragment modification
	if mods.Fragment != "" {
		modifiedReq.URL.Fragment = mods.Fragment
	}

	// Apply method modification
	if mods.Method != "" {
		modifiedReq.Method = strings.ToUpper(mods.Method)
	}

	// Apply header modifications
	for _, headerName := range mods.DeleteHeaders {
		modifiedReq.Header.Del(headerName)
	}
	for k, v := range mods.SetHeaders {
		modifiedReq.Header.Set(k, v)
	}
	for k, v := range mods.AddHeaders {
		modifiedReq.Header.Add(k, v)
	}

	// Apply query parameter modifications
	if len(mods.SetQuery) > 0 || len(mods.AddQuery) > 0 || len(mods.DeleteQuery) > 0 {
		query := modifiedReq.URL.Query()

		// Delete first
		for _, param := range mods.DeleteQuery {
			query.Del(param)
		}

		// Then set (overwrites)
		for k, v := range mods.SetQuery {
			query.Set(k, v)
		}

		// Then add (appends)
		for k, v := range mods.AddQuery {
			query.Add(k, v)
		}

		modifiedReq.URL.RawQuery = query.Encode()
	}

	// Apply form parameter modifications
	if len(mods.SetForm) > 0 || len(mods.AddForm) > 0 || len(mods.DeleteForm) > 0 {
		if err := applyFormModifications(modifiedReq, mods); err != nil {
			return nil, fmt.Errorf("failed to apply form modifications: %w", err)
		}
	}

	// Apply body modifications
	if mods.BodyRemove || mods.BodyReplace != "" || mods.BodyReplaceJSON != "" || mods.BodyReplaceBase64 != "" {
		if err := applyBodyModifications(modifiedReq, mods); err != nil {
			return nil, fmt.Errorf("failed to apply body modifications: %w", err)
		}
	}

	return modifiedReq, nil
}

// applyFormModifications applies form parameter modifications to the request
func applyFormModifications(req *http.Request, mods *ModificationResult) error {
	// Set content type if not already set
	contentType := req.Header.Get("Content-Type")
	if contentType == "" || !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Read existing body if present
	var bodyBytes []byte
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read body: %w", err)
		}
		req.Body.Close()
		bodyBytes = body
	}

	// Parse existing form data
	var form url.Values
	if len(bodyBytes) > 0 {
		parsedForm, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			form = make(url.Values)
		} else {
			form = parsedForm
		}
	} else {
		form = make(url.Values)
	}

	// Apply modifications: delete, set, add
	for _, name := range mods.DeleteForm {
		form.Del(name)
	}
	for name, value := range mods.SetForm {
		form.Set(name, value)
	}
	for name, value := range mods.AddForm {
		form.Add(name, value)
	}

	// Encode form and update body
	encoded := form.Encode()
	newBodyBytes := []byte(encoded)
	req.Body = io.NopCloser(bytes.NewReader(newBodyBytes))
	req.ContentLength = int64(len(newBodyBytes))
	req.Header.Set("Content-Length", strconv.Itoa(len(newBodyBytes)))

	return nil
}

// applyBodyModifications applies body modifications to the request
func applyBodyModifications(req *http.Request, mods *ModificationResult) error {
	var bodyBytes []byte

	// Priority: BodyReplaceBase64 > BodyReplaceJSON > BodyReplace > BodyRemove
	if mods.BodyReplaceBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(mods.BodyReplaceBase64)
		if err != nil {
			return fmt.Errorf("failed to decode base64 body: %w", err)
		}
		bodyBytes = decoded
	} else if mods.BodyReplaceJSON != "" {
		// Validate JSON
		if !json.Valid([]byte(mods.BodyReplaceJSON)) {
			return fmt.Errorf("invalid JSON body")
		}
		bodyBytes = []byte(mods.BodyReplaceJSON)
		req.Header.Set("Content-Type", "application/json")
	} else if mods.BodyReplace != "" {
		bodyBytes = []byte(mods.BodyReplace)
	} else if mods.BodyRemove {
		bodyBytes = []byte{}
	}

	// Update request body
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))

	if len(bodyBytes) == 0 {
		req.Header.Del("Content-Length")
	} else {
		req.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	}

	return nil
}

// normalizeHeaderMap normalizes header names to lowercase for consistency
// http.Header is case-insensitive, but normalization ensures consistency across the codebase
func normalizeHeaderMap(headers map[string]string) map[string]string {
	normalized := make(map[string]string, len(headers))
	for k, v := range headers {
		normalized[strings.ToLower(k)] = v
	}
	return normalized
}

// normalizeHeaderSlice normalizes header names to lowercase for consistency
func normalizeHeaderSlice(headers []string) []string {
	normalized := make([]string, len(headers))
	for i, h := range headers {
		normalized[i] = strings.ToLower(h)
	}
	return normalized
}

// ApplyModifications is a helper function that applies ModificationResult to a request
func ApplyModifications(req *http.Request, mods *ModificationResult) (*http.Request, error) {
	return applyModifications(req, mods)
}

// ParseModificationScript parses a Lua script and returns a Modifier
func ParseModificationScript(script string) (Modifier, error) {
	return NewModifier(script)
}

// ModifyRequest is a convenience function that creates a modifier and applies it to a request
func ModifyRequest(req *http.Request, script string) (*http.Request, error) {
	modifier, err := NewModifier(script)
	if err != nil {
		return req, fmt.Errorf("failed to create modifier: %w", err)
	}
	return modifier.Modify(req)
}
