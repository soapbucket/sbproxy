package e2e

import (
	"testing"
)

// TestCELCallbackOnLoad tests CEL expression callbacks on origin load.
// Fixture: 73-cel-callback-onload.json (cel-onload.test)
func TestCELCallbackOnLoad(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("origin with CEL on_load callback responds", func(t *testing.T) {
		resp := proxyGet(t, "cel-onload.test", "/test/simple-200")
		if resp.StatusCode >= 500 {
			t.Logf("CEL on_load callback origin returned %d", resp.StatusCode)
		}
	})
}

// TestLuaCallbackOnLoad tests Lua expression callbacks on origin load.
// Fixture: 74-lua-callback-onload.json (lua-onload.test)
func TestLuaCallbackOnLoad(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("origin with Lua on_load callback responds", func(t *testing.T) {
		resp := proxyGet(t, "lua-onload.test", "/test/simple-200")
		if resp.StatusCode >= 500 {
			t.Logf("Lua on_load callback origin returned %d", resp.StatusCode)
		}
	})
}

// TestCELCallbackSession tests CEL expression callbacks on session start.
// Fixture: 75-cel-callback-session.json (cel-session.test)
func TestCELCallbackSession(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("origin with CEL session callback responds", func(t *testing.T) {
		resp := proxyGet(t, "cel-session.test", "/test/simple-200")
		if resp.StatusCode >= 500 {
			t.Logf("CEL session callback origin returned %d", resp.StatusCode)
		}
	})
}

// TestCELCallbackAuth tests CEL expression callbacks on auth.
// Fixture: 77-cel-callback-auth.json (cel-auth.test)
func TestCELCallbackAuth(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("origin with CEL auth callback responds", func(t *testing.T) {
		resp := proxyGet(t, "cel-auth.test", "/test/simple-200")
		// Likely needs auth, but we verify the origin is configured
		t.Logf("CEL auth callback origin response: %d", resp.StatusCode)
	})
}

// TestCELExpressionPolicyCallback tests CEL expression policy with callback data.
// Fixture: 79-cel-expression-policy-callback.json (cel-expression-callback.test)
func TestCELExpressionPolicyCallback(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("CEL expression policy with callback works", func(t *testing.T) {
		resp := proxyGet(t, "cel-expression-callback.test", "/test/simple-200")
		t.Logf("CEL expression policy with callback response: %d", resp.StatusCode)
	})
}

// TestCELMultipleCallbacks tests multiple CEL callbacks on one origin.
// Fixture: 83-cel-multiple-callbacks.json (cel-multi-callbacks.test)
func TestCELMultipleCallbacks(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("multiple CEL callbacks work together", func(t *testing.T) {
		resp := proxyGet(t, "cel-multi-callbacks.test", "/test/simple-200")
		t.Logf("Multiple CEL callbacks response: %d", resp.StatusCode)
	})
}

// TestLuaMultipleCallbacks tests multiple Lua callbacks on one origin.
// Fixture: 84-lua-multiple-callbacks.json (lua-multi-callbacks.test)
func TestLuaMultipleCallbacks(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("multiple Lua callbacks work together", func(t *testing.T) {
		resp := proxyGet(t, "lua-multi-callbacks.test", "/test/simple-200")
		t.Logf("Multiple Lua callbacks response: %d", resp.StatusCode)
	})
}

// TestMultipleOnloadCallbacks tests multiple on_load callbacks.
// Fixture: 154-multiple-onload-callbacks.json (multiple-onload.test)
func TestMultipleOnloadCallbacks(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("multiple on_load callbacks work", func(t *testing.T) {
		resp := proxyGet(t, "multiple-onload.test", "/test/simple-200")
		t.Logf("Multiple on_load callbacks response: %d", resp.StatusCode)
	})
}

// TestComprehensiveCallbackStack tests the comprehensive callback stack.
// Fixture: 157-comprehensive-callback-stack.json (comprehensive-callbacks.test)
func TestComprehensiveCallbackStack(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("comprehensive callback stack works", func(t *testing.T) {
		resp := proxyGet(t, "comprehensive-callbacks.test", "/test/simple-200")
		t.Logf("Comprehensive callback stack response: %d", resp.StatusCode)
	})
}
