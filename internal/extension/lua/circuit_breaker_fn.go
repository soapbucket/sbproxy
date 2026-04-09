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

// CircuitBreakerFn determines if the circuit should break for a failure using Lua scripts.
type CircuitBreakerFn interface {
	// ShouldBreak evaluates if the given response/error should count as a circuit breaker failure.
	// Returns true if the circuit should break, false if it should be ignored.
	ShouldBreak(statusCode int, errMessage string, req *http.Request) bool
}

type circuitBreakerFn struct {
	script  string
	timeout time.Duration
}

// ShouldBreak evaluates the circuit breaker script.
// The script must define a function: function should_break_circuit(status, error, ctx)
// that returns a boolean indicating if the failure should count toward breaking the circuit.
func (cb *circuitBreakerFn) ShouldBreak(statusCode int, errMessage string, req *http.Request) bool {
	L := newSandboxedState()
	defer L.Close()

	// Set up timeout context
	ctx, cancel := context.WithTimeout(context.Background(), cb.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Measure Lua execution time
	startTime := time.Now()

	// Load the script
	if err := L.DoString(cb.script); err != nil {
		duration := time.Since(startTime).Seconds()
		origin := getOriginFromRequest(req)
		metric.LuaExecutionTime(origin, "circuit_breaker_fn", duration)
		slog.Debug("error loading circuit breaker script", "error", err)
		return true // Break on error for safety
	}

	// Get the should_break_circuit function
	breakFn := L.GetGlobal("should_break_circuit")
	if breakFn.Type() != lua.LTFunction {
		duration := time.Since(startTime).Seconds()
		origin := getOriginFromRequest(req)
		metric.LuaExecutionTime(origin, "circuit_breaker_fn", duration)
		slog.Debug("should_break_circuit function not found")
		return true // Break on error for safety
	}

	// Build request context and tables
	rc := NewRequestContext(req)
	ctxTable := rc.BuildContextTable(L)

	// Build status and error values
	statusVal := lua.LNumber(statusCode)
	var errVal lua.LValue = lua.LString(errMessage)
	if errMessage == "" {
		errVal = lua.LNil
	}

	// Call the should_break_circuit function
	L.Push(breakFn)
	L.Push(statusVal)
	L.Push(errVal)
	L.Push(ctxTable)

	if err := L.PCall(3, 1, nil); err != nil {
		duration := time.Since(startTime).Seconds()
		origin := getOriginFromRequest(req)
		metric.LuaExecutionTime(origin, "circuit_breaker_fn", duration)
		slog.Debug("error calling should_break_circuit", "error", err)
		return true // Break on error for safety
	}

	duration := time.Since(startTime).Seconds()
	origin := getOriginFromRequest(req)
	metric.LuaExecutionTime(origin, "circuit_breaker_fn", duration)

	// Get the return value
	if L.GetTop() == 0 {
		slog.Debug("should_break_circuit did not return a value")
		return true // Break on error for safety
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Check if it's a boolean
	if boolVal, ok := ret.(lua.LBool); ok {
		return bool(boolVal)
	}

	slog.Debug("should_break_circuit did not return a boolean", "got_type", ret.Type())
	return true // Break on error for safety
}

// NewCircuitBreakerFn creates a new circuit breaker function with the default timeout.
func NewCircuitBreakerFn(script string) (CircuitBreakerFn, error) {
	return NewCircuitBreakerFnWithTimeout(script, DefaultTimeout)
}

// NewCircuitBreakerFnWithTimeout creates a new circuit breaker function with a custom timeout.
func NewCircuitBreakerFnWithTimeout(script string, timeout time.Duration) (CircuitBreakerFn, error) {
	// Validate the script
	L := newSandboxedState()
	defer L.Close()

	if err := L.DoString(script); err != nil {
		return nil, fmt.Errorf("lua: script compilation error: %w", err)
	}

	// Validate that should_break_circuit function exists
	breakFn := L.GetGlobal("should_break_circuit")
	if breakFn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("lua: missing required function 'should_break_circuit' in circuit breaker script")
	}

	return &circuitBreakerFn{
		script:  script,
		timeout: timeout,
	}, nil
}
