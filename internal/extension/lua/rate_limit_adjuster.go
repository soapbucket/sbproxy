// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	lua "github.com/yuin/gopher-lua"
)

// RateLimitAdjustment represents adjusted rate limit values.
type RateLimitAdjustment struct {
	RequestsPerMinute int
	RequestsPerHour   int
	RequestsPerDay    int
	BurstSize         int
}

// RateLimitAdjuster adjusts rate limits for requests using Lua scripts.
type RateLimitAdjuster interface {
	// AdjustRateLimits returns adjusted rate limit values for a request, or nil to use defaults.
	AdjustRateLimits(*http.Request) (*RateLimitAdjustment, error)
}

type rateLimitAdjuster struct {
	script  string
	timeout time.Duration
}

// AdjustRateLimits adjusts rate limits using the Lua script.
// The script must define a function: function adjust_rate_limit(req, ctx)
// that returns a table with limit fields (any subset is valid).
func (a *rateLimitAdjuster) AdjustRateLimits(req *http.Request) (*RateLimitAdjustment, error) {
	L := newSandboxedState()
	defer L.Close()

	// Set up timeout context
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Measure Lua execution time
	startTime := time.Now()

	// Load the script
	if err := L.DoString(a.script); err != nil {
		duration := time.Since(startTime).Seconds()
		origin := getOriginFromRequest(req)
		metric.LuaExecutionTime(origin, "rate_limit_adjuster", duration)
		slog.Debug("error loading rate limit adjuster script", "error", err)
		return nil, err
	}

	// Get the adjust_rate_limit function
	adjustFn := L.GetGlobal("adjust_rate_limit")
	if adjustFn.Type() != lua.LTFunction {
		duration := time.Since(startTime).Seconds()
		origin := getOriginFromRequest(req)
		metric.LuaExecutionTime(origin, "rate_limit_adjuster", duration)
		slog.Debug("adjust_rate_limit function not found")
		return nil, fmt.Errorf("lua: missing required function 'adjust_rate_limit'")
	}

	// Build request context and tables
	rc := NewRequestContext(req)
	reqTable := createRequestTable(L, req)
	ctxTable := rc.BuildContextTable(L)

	// Call the adjust_rate_limit function
	L.Push(adjustFn)
	L.Push(reqTable)
	L.Push(ctxTable)

	if err := L.PCall(2, 1, nil); err != nil {
		duration := time.Since(startTime).Seconds()
		origin := getOriginFromRequest(req)
		metric.LuaExecutionTime(origin, "rate_limit_adjuster", duration)
		slog.Debug("error calling adjust_rate_limit", "error", err)
		return nil, err
	}

	duration := time.Since(startTime).Seconds()
	origin := getOriginFromRequest(req)
	metric.LuaExecutionTime(origin, "rate_limit_adjuster", duration)

	// Get the return value
	if L.GetTop() == 0 {
		slog.Debug("adjust_rate_limit did not return a value")
		return nil, nil
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Handle nil return
	if ret == lua.LNil {
		return nil, nil
	}

	// Extract rate limits from the returned table
	table, ok := ret.(*lua.LTable)
	if !ok {
		slog.Debug("adjust_rate_limit did not return a table", "got_type", ret.Type())
		return nil, nil
	}

	result := &RateLimitAdjustment{}
	hasFields := false

	// Extract requests_per_minute
	if val := L.GetField(table, "requests_per_minute"); val != lua.LNil {
		if num, ok := val.(lua.LNumber); ok {
			result.RequestsPerMinute = int(num)
			hasFields = true
		}
	}

	// Extract requests_per_hour
	if val := L.GetField(table, "requests_per_hour"); val != lua.LNil {
		if num, ok := val.(lua.LNumber); ok {
			result.RequestsPerHour = int(num)
			hasFields = true
		}
	}

	// Extract requests_per_day
	if val := L.GetField(table, "requests_per_day"); val != lua.LNil {
		if num, ok := val.(lua.LNumber); ok {
			result.RequestsPerDay = int(num)
			hasFields = true
		}
	}

	// Extract burst_size
	if val := L.GetField(table, "burst_size"); val != lua.LNil {
		if num, ok := val.(lua.LNumber); ok {
			result.BurstSize = int(num)
			hasFields = true
		}
	}

	if hasFields {
		return result, nil
	}

	return nil, nil
}

// NewRateLimitAdjuster creates a new rate limit adjuster with the default timeout.
func NewRateLimitAdjuster(script string) (RateLimitAdjuster, error) {
	return NewRateLimitAdjusterWithTimeout(script, DefaultTimeout)
}

// NewRateLimitAdjusterWithTimeout creates a new rate limit adjuster with a custom timeout.
func NewRateLimitAdjusterWithTimeout(script string, timeout time.Duration) (RateLimitAdjuster, error) {
	// Validate the script
	L := newSandboxedState()
	defer L.Close()

	if err := L.DoString(script); err != nil {
		return nil, fmt.Errorf("lua: script compilation error: %w", err)
	}

	// Validate that adjust_rate_limit function exists
	adjustFn := L.GetGlobal("adjust_rate_limit")
	if adjustFn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("lua: missing required function 'adjust_rate_limit'")
	}

	return &rateLimitAdjuster{
		script:  script,
		timeout: timeout,
	}, nil
}

// Helper function to get origin from request
func getOriginFromRequest(req *http.Request) string {
	if req == nil {
		return "unknown"
	}

	requestData := reqctx.GetRequestData(req.Context())
	if requestData != nil && requestData.Config != nil {
		if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
			return id
		}
	}

	if req.Host != "" {
		return req.Host
	}

	return "unknown"
}
