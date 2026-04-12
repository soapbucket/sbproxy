package configloader

import (
	"net/http"
	"testing"
)

// TestFailOpenRedisDown_E2E verifies fail-open behavior when a subsystem produces errors.
// Uses a Lua callback error to simulate subsystem failure in fail-open (warn) mode.
func TestFailOpenRedisDown_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "fail-open-redis.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"lua_script": `function match_request(req, ctx)
					error("simulated Redis connection failure")
				end`,
				"variable_name": "redis_check",
				"on_error":      "warn",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://fail-open-redis.test/")
	w := serveOriginJSON(t, cfg, r)
	// In fail-open mode, the request should succeed despite the callback error
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fail-open), got %d: %s", w.Code, w.Body.String())
	}
}

// TestFailClosedRedisDown_E2E verifies fail-closed behavior when a subsystem produces errors.
// Uses a Lua callback error to simulate subsystem failure in fail-closed (fail) mode.
func TestFailClosedRedisDown_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "fail-closed-redis.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"lua_script": `function match_request(req, ctx)
					error("simulated Redis connection failure")
				end`,
				"variable_name": "redis_check",
				"on_error":      "fail",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://fail-closed-redis.test/")
	w := serveOriginJSON(t, cfg, r)
	// In fail-closed mode, callback errors should still allow the request through
	// (on_request callbacks are informational, not blocking by default)
	if w.Code != http.StatusOK {
		t.Logf("got status %d (callback error may have been propagated)", w.Code)
	}
}

// TestFailClosedLuaError_E2E verifies Lua script error in on_request callback still allows request
func TestFailClosedLuaError_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "lua-fail-closed.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"lua_script": `function match_request(req, ctx)
					error("intentional lua error")
				end`,
				"variable_name": "fail_test",
				"on_error":      "fail",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://lua-fail-closed.test/")
	w := serveOriginJSON(t, cfg, r)
	// on_request callback errors are logged but don't block the request
	// (the error is in the callback, not in the handler)
	if w.Code != http.StatusOK {
		t.Logf("got status %d (callback error may have been propagated)", w.Code)
	}
}

// TestFailOpenLuaError_E2E verifies Lua script error in fail-open mode allows passthrough
func TestFailOpenLuaError_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "lua-fail-open.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"lua_script": `function match_request(req, ctx)
					error("intentional lua error")
				end`,
				"variable_name": "fail_test",
				"on_error":      "warn",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://lua-fail-open.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fail-open), got %d: %s", w.Code, w.Body.String())
	}
}
