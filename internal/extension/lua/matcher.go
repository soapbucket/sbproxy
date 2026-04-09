// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

const (
	// DefaultTimeout is the default execution timeout for Lua scripts
	DefaultTimeout = 100 * time.Millisecond
	// MaxMemory is the maximum memory in bytes that a Lua state can use (approximate)
	MaxMemory = 10 * 1024 * 1024 // 10MB
	// MaxInstructions is the maximum number of instructions a script can execute
	MaxInstructions = 100000
)

// ErrTimeout is returned when Lua script execution exceeds the timeout
var ErrTimeout = errors.New("lua: execution timeout")

// ErrWrongType is returned when a Lua script does not return a boolean type
var ErrWrongType = errors.New("lua: script must return a boolean value")

// Matcher evaluates Lua expressions against HTTP requests.
type Matcher interface {
	// Match evaluates the Lua script against the given HTTP request.
	// Returns true if the script evaluates to true, false otherwise.
	// If evaluation fails, returns false and logs the error.
	Match(*http.Request) bool
}

type matcher struct {
	script  string
	timeout time.Duration
}

// Match evaluates the Lua script against the HTTP request
// The script must define a function: function match_request(req, ctx)
// that returns a boolean value
func (m *matcher) Match(req *http.Request) bool {
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
		metric.LuaExecutionTime(origin, "matcher", duration)

		slog.Debug("error loading script", "url", req.URL, "error", err)
		return false
	}

	// Get the match_request function
	matchFn := L.GetGlobal("match_request")
	if matchFn.Type() != lua.LTFunction {
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
		metric.LuaExecutionTime(origin, "matcher", duration)

		slog.Debug("match_request function not found", "url", req.URL)
		return false
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

	// Call the match_request function with req and ctx tables
	L.Push(matchFn)
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
		metric.LuaExecutionTime(origin, "matcher", duration)

		slog.Debug("error calling match_request", "url", req.URL, "error", err)
		return false
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
	metric.LuaExecutionTime(origin, "matcher", duration)

	// Get the return value from the stack
	if L.GetTop() == 0 {
		slog.Debug("match_request did not return a value", "url", req.URL)
		return false
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Check if it's a boolean
	if boolVal, ok := ret.(lua.LBool); ok {
		return bool(boolVal)
	}

	slog.Debug("match_request did not return boolean", "url", req.URL, "got_type", ret.Type())
	return false
}

// NewMatcher creates a new Lua matcher for HTTP requests.
// The script must define a function: function match_request(req, ctx)
// that returns a boolean value.
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
// The ctx table (ScriptContext) has:
//   - request_ip: string
//   - location: table (country, country_code, continent, asn, etc.)
//   - user_agent: table (family, major, minor, os_family, device_family, etc.)
//   - fingerprint: table (hash, composite, ip_hash, etc.)
//   - session: table (id, expires, is_authenticated, auth, data, visited, etc.)
//   - auth: table (data)
//   - config: table (user-defined config)
//   - request_data: table (data from on_request callback)
//   - variables: table (user-defined variables)
//   - secrets: table (vault paths)
//   - env: table (per-origin env variables)
//   - features: table (workspace feature flags)
//   - server: table (server-level variables)
//   - request: table (basic request info: method, path, host, headers, query)
//
// The sandbox provides access to:
//   - Basic string functions (string.find, string.match, string.sub, etc.)
//   - Pattern matching with string.match
//   - Table operations
//   - Basic operators and control flow
//
// Blocked for security:
//   - File I/O (io, os)
//   - Network operations
//   - Package loading (require, dofile, loadfile)
//   - Debug functions
//   - Dangerous functions (getmetatable, setmetatable, rawset, etc.)
//
// Example scripts:
//
//	function match_request(req, ctx)
//	  return req.method == "GET"
//	end
//
//	function match_request(req, ctx)
//	  return ctx.location.country_code == "US"
//	end
//
//	function match_request(req, ctx)
//	  local ct = req.headers["content-type"] or ""
//	  return string.match(ct, "application/json") ~= nil
//	end
//
//	function match_request(req, ctx)
//	  return string.sub(req.path, 1, 5) == "/api/" and ctx.user_agent.family == "Chrome"
//	end
//
//	function match_request(req, ctx)
//	  return ctx.session and ctx.session.is_authenticated
//	end
func NewMatcher(script string) (Matcher, error) {
	return NewMatcherWithTimeout(script, DefaultTimeout)
}

// NewMatcherWithTimeout creates a new Lua matcher with a custom timeout
func NewMatcherWithTimeout(script string, timeout time.Duration) (Matcher, error) {
	script = wrapMatcherScript(script)
	// Validate the script by running it in a test state
	L := newSandboxedState()
	defer L.Close()

	// Try to compile and check for match_request function
	if err := L.DoString(script); err != nil {
		return nil, fmt.Errorf("lua: script compilation error: %w", err)
	}

	// Validate that match_request function exists
	matchFn := L.GetGlobal("match_request")
	if matchFn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("lua: missing required function 'match_request' in matcher script")
	}

	return &matcher{
		script:  script,
		timeout: timeout,
	}, nil
}

// newSandboxedState creates a new Lua state with security restrictions
func (m *matcher) newSandboxedState() *lua.LState {
	return newSandboxedState()
}

// newSandboxedState creates a new sandboxed Lua state
func newSandboxedState() *lua.LState {
	// Create state with limited resources
	// Note: gopher-lua uses context timeout for execution limits
	L := lua.NewState()

	// Remove dangerous modules and functions
	L.SetGlobal("dofile", lua.LNil)
	L.SetGlobal("loadfile", lua.LNil)
	L.SetGlobal("load", lua.LNil)
	L.SetGlobal("loadstring", lua.LNil)
	L.SetGlobal("require", lua.LNil)
	L.SetGlobal("module", lua.LNil)
	L.SetGlobal("rawset", lua.LNil)
	L.SetGlobal("rawget", lua.LNil)
	L.SetGlobal("setmetatable", lua.LNil)
	L.SetGlobal("getmetatable", lua.LNil)
	L.SetGlobal("rawequal", lua.LNil)

	// Remove dangerous packages
	L.SetGlobal("io", lua.LNil)
	L.SetGlobal("os", lua.LNil)
	L.SetGlobal("package", lua.LNil)
	L.SetGlobal("debug", lua.LNil)

	// Keep only safe functions from string library
	strTable := L.NewTable()
	origStr := L.GetGlobal("string")
	if tbl, ok := origStr.(*lua.LTable); ok {
		// Safe string functions
		safeFuncs := []string{
			"byte", "char", "find", "format", "gmatch", "gsub",
			"len", "lower", "match", "rep", "reverse", "sub", "upper",
		}
		for _, name := range safeFuncs {
			if fn := L.GetField(tbl, name); fn != lua.LNil {
				strTable.RawSetString(name, fn)
			}
		}
	}
	L.SetGlobal("string", strTable)

	// Keep safe math library
	// Keep safe table library (already safe)

	// Register IP functions
	RegisterIPFunctions(L)

	return L
}

// NewSandboxedState creates a new sandboxed Lua state for use by external packages.
// This is the exported counterpart of newSandboxedState.
func NewSandboxedState() *lua.LState {
	return newSandboxedState()
}

// ConvertGoToLua converts a Go value to a Lua value. Exported wrapper for external packages.
func ConvertGoToLua(L *lua.LState, value interface{}) lua.LValue {
	return convertGoToLua(L, value)
}

// ConvertLuaToGo converts a Lua value to a Go value. Exported wrapper for external packages.
func ConvertLuaToGo(L *lua.LState, value lua.LValue) interface{} {
	return convertLuaToGo(L, value)
}


// createRequestTable creates a Lua table with request data
func createRequestTable(L *lua.LState, req *http.Request) *lua.LTable {
	reqTable := L.NewTable()

	if req == nil {
		// Return empty table for validation
		reqTable.RawSetString("headers", L.NewTable())
		reqTable.RawSetString("path", lua.LString(""))
		reqTable.RawSetString("method", lua.LString(""))
		reqTable.RawSetString("host", lua.LString(""))
		reqTable.RawSetString("protocol", lua.LString(""))
		reqTable.RawSetString("scheme", lua.LString(""))
		reqTable.RawSetString("query", lua.LString(""))
		reqTable.RawSetString("id", lua.LString(""))
		reqTable.RawSetString("size", lua.LNumber(0))
		reqTable.RawSetString("data", L.NewTable()) // Empty data table for validation
		return reqTable
	}

	// Store headers under lowercase keys only (single entry per header).
	// Lua scripts use: req.headers["content-type"], req.headers["x-admin"]
	headers := L.NewTable()
	for k, v := range req.Header {
		headers.RawSetString(strings.ToLower(k), lua.LString(strings.Join(v, ",")))
	}
	reqTable.RawSetString("headers", headers)

	// Set request fields
	reqTable.RawSetString("path", lua.LString(req.URL.Path))
	reqTable.RawSetString("method", lua.LString(req.Method))
	reqTable.RawSetString("host", lua.LString(req.Host))
	reqTable.RawSetString("protocol", lua.LString(req.Proto))
	reqTable.RawSetString("scheme", lua.LString(req.URL.Scheme))
	reqTable.RawSetString("query", lua.LString(req.URL.Query().Encode()))

	reqTable.RawSetString("size", lua.LNumber(req.ContentLength))

	// Add request ID and Snapshot fields if available
	if requestData := reqctx.GetRequestData(req.Context()); requestData != nil {
		reqTable.RawSetString("id", lua.LString(requestData.ID))

		// Add request.data field pointing to RequestData.Data
		if requestData.Data != nil {
			reqTable.RawSetString("data", convertMapToLuaTable(L, requestData.Data))
		} else {
			reqTable.RawSetString("data", L.NewTable())
		}

		// Add Snapshot fields (body_json, is_json, body, method override)
		if requestData.Snapshot != nil {
			snap := requestData.Snapshot
			reqTable.RawSetString("is_json", lua.LBool(snap.IsJSON))
			if snap.BodyJSON != nil {
				reqTable.RawSetString("body_json", convertInterfaceToLua(L, snap.BodyJSON))
			}
			if snap.Body != nil {
				reqTable.RawSetString("body", lua.LString(string(snap.Body)))
			}
			if snap.ContentType != "" {
				reqTable.RawSetString("content_type", lua.LString(snap.ContentType))
			}
			if snap.RemoteAddr != "" {
				reqTable.RawSetString("remote_addr", lua.LString(snap.RemoteAddr))
			}
			// Snapshot method overrides live request method (pre-modification snapshot)
			if snap.Method != "" {
				reqTable.RawSetString("method", lua.LString(snap.Method))
			}
		}
	} else {
		reqTable.RawSetString("id", lua.LString(""))
		reqTable.RawSetString("data", L.NewTable())
	}

	return reqTable
}

// createCookiesTable creates a Lua table with cookies from the request
func createCookiesTable(L *lua.LState, req *http.Request) *lua.LTable {
	cookiesTable := L.NewTable()

	if req == nil {
		return cookiesTable
	}

	// Extract all cookies
	for _, cookie := range req.Cookies() {
		cookiesTable.RawSetString(cookie.Name, lua.LString(cookie.Value))
	}

	return cookiesTable
}

// createParamsTable creates a Lua table with query parameters from the request
func createParamsTable(L *lua.LState, req *http.Request) *lua.LTable {
	paramsTable := L.NewTable()

	if req == nil || req.URL == nil {
		return paramsTable
	}

	// Extract all query parameters
	for k, v := range req.URL.Query() {
		if len(v) > 0 {
			paramsTable.RawSetString(k, lua.LString(v[0])) // Take the first value if multiple
		}
	}

	return paramsTable
}
