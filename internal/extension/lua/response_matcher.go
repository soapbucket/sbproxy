// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// ResponseMatcher evaluates Lua scripts against HTTP responses.
type ResponseMatcher interface {
	// Match evaluates the Lua script against the given HTTP response.
	// Returns true if the script evaluates to true, false otherwise.
	// If evaluation fails, returns false and logs the error.
	Match(*http.Response) bool
}

type responseMatcher struct {
	script  string
	timeout time.Duration
}

// Match evaluates the Lua script against the HTTP response
// The script must define a function: function match_response(resp, ctx)
// where ctx includes response_status and response_headers
func (m *responseMatcher) Match(resp *http.Response) bool {
	L := m.newSandboxedState()
	defer L.Close()

	// Set up timeout context
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Load the script
	if err := L.DoString(m.script); err != nil {
		slog.Debug("error loading response script", "url", resp.Request.URL, "error", err)
		return false
	}

	// Get the match_response function
	matchFn := L.GetGlobal("match_response")
	if matchFn.Type() != lua.LTFunction {
		slog.Debug("match_response function not found", "url", resp.Request.URL)
		return false
	}

	// Build request context
	req := resp.Request
	if req == nil {
		return false
	}

	rc := NewRequestContext(req)
	rc.PopulateLuaState(L)

	// Build context table with response info
	ctxTable := rc.BuildContextTable(L)
	ctxTable.RawSetString("ip", L.GetGlobal("ip"))

	// Add response fields to context
	if resp.StatusCode > 0 {
		ctxTable.RawSetString("response_status", lua.LNumber(resp.StatusCode))
	}

	// Store response headers under lowercase keys only
	respHeadersTable := L.NewTable()
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeadersTable.RawSetString(strings.ToLower(k), lua.LString(v[0]))
		}
	}
	ctxTable.RawSetString("response_headers", respHeadersTable)

	// Build response table
	respTable := m.createResponseMatcherTable(L, resp)
	L.SetGlobal("response", respTable)
	L.SetGlobal("request", createRequestTable(L, req))
	L.SetGlobal("cookies", createCookiesTable(L, req))
	L.SetGlobal("params", createParamsTable(L, req))

	// Call the match_response function with resp and ctx tables
	L.Push(matchFn)
	L.Push(respTable)
	L.Push(ctxTable)

	// Execute the function call
	if err := L.PCall(2, 1, nil); err != nil {
		slog.Debug("error calling match_response", "url", resp.Request.URL, "error", err)
		return false
	}

	// Get the return value from the stack
	if L.GetTop() == 0 {
		slog.Debug("match_response did not return a value", "url", resp.Request.URL)
		return false
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Check if it's a boolean
	if boolVal, ok := ret.(lua.LBool); ok {
		return bool(boolVal)
	}

	slog.Debug("match_response did not return boolean", "url", resp.Request.URL, "got_type", ret.Type())
	return false
}


// createResponseMatcherTable creates a Lua table with response data for matching
func (m *responseMatcher) createResponseMatcherTable(L *lua.LState, resp *http.Response) *lua.LTable {
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

	// Store response headers under lowercase keys only
	headers := L.NewTable()
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers.RawSetString(strings.ToLower(k), lua.LString(v[0]))
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

// NewResponseMatcher creates a new Lua response matcher for HTTP responses.
// The script must define a function: function match_response(resp, ctx)
// that returns a boolean value.
//
// The resp table has the following fields:
//   - status_code: number (HTTP status code)
//   - status: string (HTTP status text, e.g., "200 OK")
//   - headers: table[string]string (response headers)
//   - body: string (response body content)
//
// The ctx table includes:
//   - All request context data (request_ip, location, user_agent, session, etc.)
//   - response_status: number (HTTP status code)
//   - response_headers: table[string]string (response headers)
//   - request: table (request info: method, path, host, headers, query)
//
// Example scripts:
//
//	function match_response(resp, ctx)
//	  return resp.status_code == 200
//	end
//
//	function match_response(resp, ctx)
//	  return resp.status_code >= 400 and resp.status_code < 500
//	end
//
//	function match_response(resp, ctx)
//	  local ct = resp.headers["content-type"] or ""
//	  return string.match(ct, "application/json") ~= nil
//	end
//
//	function match_response(resp, ctx)
//	  return resp.status_code == 200 and
//	         string.find(resp.body, "success") ~= nil and
//	         ctx.location.country_code == "US"
//	end
func NewResponseMatcher(script string) (ResponseMatcher, error) {
	return NewResponseMatcherWithTimeout(script, DefaultTimeout)
}

// NewResponseMatcherWithTimeout creates a new Lua response matcher with a custom timeout.
func NewResponseMatcherWithTimeout(script string, timeout time.Duration) (ResponseMatcher, error) {
	if script == "" {
		return nil, errors.New("lua: script cannot be empty")
	}
	script = wrapResponseMatcherScript(script)

	// Validate the script by compiling it
	L := newSandboxedState()
	defer L.Close()

	// Try to compile and check for match_response function
	if err := L.DoString(script); err != nil {
		return nil, err
	}

	// Validate that match_response function exists
	matchFn := L.GetGlobal("match_response")
	if matchFn.Type() != lua.LTFunction {
		return nil, errors.New("lua: missing required function 'match_response' in response matcher script")
	}

	return &responseMatcher{
		script:  script,
		timeout: timeout,
	}, nil
}

// newSandboxedState creates a new Lua state with security restrictions for this response matcher
func (m *responseMatcher) newSandboxedState() *lua.LState {
	return newSandboxedState()
}
