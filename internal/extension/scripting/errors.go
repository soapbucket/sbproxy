// Package scripting provides shared context types for Lua script execution across proxy components.
package scripting

import (
	"fmt"
)

// ErrScriptSyntax is returned when a Lua script has syntax errors
type ErrScriptSyntax struct {
	msg string
}

// Error performs the error operation on the ErrScriptSyntax.
func (e *ErrScriptSyntax) Error() string {
	return fmt.Sprintf("script syntax error: %s", e.msg)
}

// ErrScriptRuntime is returned when a Lua script fails at runtime
type ErrScriptRuntime struct {
	msg string
}

// Error performs the error operation on the ErrScriptRuntime.
func (e *ErrScriptRuntime) Error() string {
	return fmt.Sprintf("script runtime error: %s", e.msg)
}

// ErrScriptTimeout is returned when a Lua script execution exceeds timeout
type ErrScriptTimeout struct {
	msg string
}

// Error performs the error operation on the ErrScriptTimeout.
func (e *ErrScriptTimeout) Error() string {
	return fmt.Sprintf("script timeout: %s", e.msg)
}

// ErrMissingFunction is returned when a required function is not defined
type ErrMissingFunction struct {
	functionName string
	context      string
}

// Error performs the error operation on the ErrMissingFunction.
func (e *ErrMissingFunction) Error() string {
	if e.context != "" {
		return fmt.Sprintf("missing required function '%s' in %s script", e.functionName, e.context)
	}
	return fmt.Sprintf("missing required function '%s'", e.functionName)
}

// NewMissingFunction creates and initializes a new MissingFunction.
func NewMissingFunction(functionName, context string) *ErrMissingFunction {
	return &ErrMissingFunction{
		functionName: functionName,
		context:      context,
	}
}

// NewScriptSyntax creates and initializes a new ScriptSyntax.
func NewScriptSyntax(msg string) error {
	return &ErrScriptSyntax{msg: msg}
}

// NewScriptRuntime creates and initializes a new ScriptRuntime.
func NewScriptRuntime(msg string) error {
	return &ErrScriptRuntime{msg: msg}
}

// NewScriptTimeout creates and initializes a new ScriptTimeout.
func NewScriptTimeout(msg string) error {
	return &ErrScriptTimeout{msg: msg}
}


// IsScriptError checks if an error is a scripting-related error
func IsScriptError(err error) bool {
	if err == nil {
		return false
	}
	_, ok1 := err.(*ErrScriptSyntax)
	_, ok2 := err.(*ErrScriptRuntime)
	_, ok3 := err.(*ErrScriptTimeout)
	_, ok4 := err.(*ErrMissingFunction)
	return ok1 || ok2 || ok3 || ok4
}
