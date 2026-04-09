// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// RouteMatcher determines if a request should be routed to a specific target using Lua scripts.
type RouteMatcher interface {
	// Match evaluates the Lua script to determine if the request matches this route.
	Match(*http.Request) bool
}

type routeMatcher struct {
	script  string
	timeout time.Duration
}

// Match evaluates the route selection script.
// The script must define a function: function select_route(req, ctx)
// that returns a boolean indicating if the request should be routed to this target.
func (m *routeMatcher) Match(req *http.Request) bool {
	L := newSandboxedState()
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
		origin := getOriginFromRequest(req)
		metric.LuaExecutionTime(origin, "route_matcher", duration)
		slog.Debug("error loading route matcher script", "error", err)
		return false
	}

	// Get the select_route function
	selectFn := L.GetGlobal("select_route")
	if selectFn.Type() != lua.LTFunction {
		duration := time.Since(startTime).Seconds()
		origin := getOriginFromRequest(req)
		metric.LuaExecutionTime(origin, "route_matcher", duration)
		slog.Debug("select_route function not found")
		return false
	}

	// Build request context and tables
	rc := NewRequestContext(req)
	reqTable := createRequestTable(L, req)
	ctxTable := rc.BuildContextTable(L)

	// Call the select_route function
	L.Push(selectFn)
	L.Push(reqTable)
	L.Push(ctxTable)

	if err := L.PCall(2, 1, nil); err != nil {
		duration := time.Since(startTime).Seconds()
		origin := getOriginFromRequest(req)
		metric.LuaExecutionTime(origin, "route_matcher", duration)
		slog.Debug("error calling select_route", "error", err)
		return false
	}

	duration := time.Since(startTime).Seconds()
	origin := getOriginFromRequest(req)
	metric.LuaExecutionTime(origin, "route_matcher", duration)

	// Get the return value
	if L.GetTop() == 0 {
		slog.Debug("select_route did not return a value")
		return false
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Check if it's a boolean
	if boolVal, ok := ret.(lua.LBool); ok {
		return bool(boolVal)
	}

	slog.Debug("select_route did not return a boolean", "got_type", ret.Type())
	return false
}

// NewRouteMatcher creates a new route matcher with the default timeout.
func NewRouteMatcher(script string) (RouteMatcher, error) {
	return NewRouteMatcherWithTimeout(script, DefaultTimeout)
}

// NewRouteMatcherWithTimeout creates a new route matcher with a custom timeout.
func NewRouteMatcherWithTimeout(script string, timeout time.Duration) (RouteMatcher, error) {
	// Validate the script
	L := newSandboxedState()
	defer L.Close()

	if err := L.DoString(script); err != nil {
		return nil, fmt.Errorf("lua: script compilation error: %w", err)
	}

	// Validate that select_route function exists
	selectFn := L.GetGlobal("select_route")
	if selectFn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("lua: missing required function 'select_route' in route matcher script")
	}

	return &routeMatcher{
		script:  script,
		timeout: timeout,
	}, nil
}
