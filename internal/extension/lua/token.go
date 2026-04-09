// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	lua "github.com/yuin/gopher-lua"
	"golang.org/x/net/html"
)

// TokenMatcher evaluates Lua scripts against HTML tokens.
type TokenMatcher interface {
	// Match evaluates the Lua script against the given HTML token.
	// Returns true if the script evaluates to true, false otherwise.
	// If evaluation fails, returns false and logs the error.
	Match(html.Token) bool
}

type tokenMatcher struct {
	script  string
	timeout time.Duration
}

// Match evaluates the Lua script against the HTML token
func (m *tokenMatcher) Match(token html.Token) bool {
	L := newSandboxedState()
	defer L.Close()

	// Set up timeout context
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Populate token data
	m.setTokenVar(L, token)

	// Execute the script
	if err := L.DoString(m.script); err != nil {
		slog.Debug("error evaluating token script", "token", token.Data, "error", err)
		return false
	}

	// Get the return value from the stack
	// Check if there's anything on the stack
	if L.GetTop() == 0 {
		slog.Debug("token script did not return a value", "token", token.Data)
		return false
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Check if it's a boolean
	if boolVal, ok := ret.(lua.LBool); ok {
		return bool(boolVal)
	}

	slog.Debug("token script did not return boolean", "token", token.Data, "got_type", ret.Type())
	return false
}

// NewTokenMatcher creates a new Lua matcher for HTML tokens.
// The script must return a boolean value and can access token properties
// through the 'token' table which has the following fields:
//   - data: string (tag name)
//   - attrs: table with attribute key-value pairs
//
// The sandbox provides the same security restrictions as the request matcher.
//
// Example scripts:
//
//	return token.data == "a"
//	return token.attrs.href ~= nil
//	return token.attrs.class and string.match(token.attrs.class, "button")
func NewTokenMatcher(script string) (TokenMatcher, error) {
	return NewTokenMatcherWithTimeout(script, DefaultTimeout)
}

// NewTokenMatcherWithTimeout creates a new Lua token matcher with a custom timeout
func NewTokenMatcherWithTimeout(script string, timeout time.Duration) (TokenMatcher, error) {
	// Validate the script by running it in a test state
	L := newSandboxedState()
	defer L.Close()

	// Create a dummy token table for validation
	L.SetGlobal("token", createTokenTable(L, html.Token{}))

	// Try to compile the script
	if _, err := L.LoadString(script); err != nil {
		return nil, fmt.Errorf("lua: script compilation error: %w", err)
	}

	return &tokenMatcher{
		script:  script,
		timeout: timeout,
	}, nil
}

// setTokenVar populates the Lua state with token data
func (m *tokenMatcher) setTokenVar(L *lua.LState, token html.Token) {
	L.SetGlobal("token", createTokenTable(L, token))
}

// createTokenTable creates a Lua table with token data
func createTokenTable(L *lua.LState, token html.Token) *lua.LTable {
	tokenTable := L.NewTable()

	// Set token data (tag name)
	tokenTable.RawSetString("data", lua.LString(token.Data))

	// Create attrs table
	attrs := L.NewTable()
	for _, attr := range token.Attr {
		attrs.RawSetString(attr.Key, lua.LString(attr.Val))
	}
	tokenTable.RawSetString("attrs", attrs)

	return tokenTable
}
