package configloader

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAuthentication_APIKey_E2E tests API key authentication
func TestAuthentication_APIKey_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "apikey-auth.test",
		"action":   map[string]any{"type": "echo"},
		"authentication": map[string]any{
			"type":        "api_key",
			"api_keys":    []string{"test-key-123", "test-key-456"},
			"header_name": "X-API-Key",
		},
	})

	t.Run("valid key returns 200", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://apikey-auth.test/")
		r.Header.Set("X-API-Key", "test-key-123")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("missing key returns 401", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://apikey-auth.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("invalid key returns 401", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://apikey-auth.test/")
		r.Header.Set("X-API-Key", "wrong-key")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

// TestAuthentication_BasicAuth_E2E tests basic authentication
func TestAuthentication_BasicAuth_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "basic-auth.test",
		"action":   map[string]any{"type": "echo"},
		"authentication": map[string]any{
			"type": "basic_auth",
			"users": []map[string]string{
				{"username": "admin", "password": "secret123"},
			},
		},
	})

	t.Run("valid credentials returns 200", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://basic-auth.test/")
		r.SetBasicAuth("admin", "secret123")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("missing credentials returns 401", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://basic-auth.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("wrong password returns 401", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://basic-auth.test/")
		r.SetBasicAuth("admin", "wrong")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

// TestResponseCache_E2E tests response caching with in-memory fallback cache
func TestResponseCache_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cache-e2e.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "cached-body",
			"headers":     map[string]string{"Content-Type": "text/plain"},
		},
		"response_cache": map[string]any{
			"enabled": true,
			"ttl":     "5m",
		},
	})

	compiled := compileTestOrigin(t, cfg)

	// First request: MISS
	r1 := newTestRequest(t, "GET", "http://cache-e2e.test/test")
	w1 := httptest.NewRecorder()
	compiled.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w1.Code)
	}
	if w1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected X-Cache: MISS, got %q", w1.Header().Get("X-Cache"))
	}

	// Second request: HIT
	r2 := newTestRequest(t, "GET", "http://cache-e2e.test/test")
	w2 := httptest.NewRecorder()
	compiled.ServeHTTP(w2, r2)
	if w2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected X-Cache: HIT, got %q", w2.Header().Get("X-Cache"))
	}
}

// TestRedirect_E2E tests redirect action
func TestRedirect_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "redirect.test",
		"action": map[string]any{
			"type":        "redirect",
			"url":         "https://example.com/landing",
			"status_code": 302,
		},
	})

	r := newTestRequest(t, "GET", "http://redirect.test/some/path")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "https://example.com/landing" {
		t.Fatalf("expected redirect to https://example.com/landing, got %q", loc)
	}
}

// TestStaticContent_E2E tests static file serving
func TestStaticContent_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "static.test",
		"action": map[string]any{
			"type":         "static",
			"status_code":  200,
			"content_type": "application/json",
			"body":         `{"status":"ok"}`,
		},
	})

	r := newTestRequest(t, "GET", "http://static.test/health")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Fatalf("body missing expected content: %s", w.Body.String())
	}
}

// TestSecurityHeaders_E2E tests security header injection
func TestSecurityHeaders_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "secheaders.test",
		"action":   map[string]any{"type": "echo"},
		"policies": []map[string]any{
			{
				"type": "security_headers",
				"headers": []map[string]any{
					{"name": "X-Frame-Options", "value": "DENY"},
					{"name": "X-Content-Type-Options", "value": "nosniff"},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://secheaders.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if xfo := w.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Fatalf("expected X-Frame-Options: DENY, got %q", xfo)
	}
	if xcto := w.Header().Get("X-Content-Type-Options"); xcto != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options: nosniff, got %q", xcto)
	}
}

// TestJSONProjection_E2E tests JSON field projection
func TestJSONProjection_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "jsonproj.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        `{"name":"Alice","age":30,"email":"alice@example.com","secret":"hidden"}`,
			"headers": map[string]string{
				"Content-Type": "application/json",
			},
		},
		"transforms": []map[string]any{
			{
				"type":    "json_projection",
				"include": []string{"name", "age"},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://jsonproj.test/data")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}
	if _, ok := result["name"]; !ok {
		t.Fatal("expected 'name' field in projected response")
	}
	if _, ok := result["secret"]; ok {
		t.Fatal("'secret' field should have been removed by projection")
	}
}

// TestLoadBalancing_E2E tests load balancing across multiple backends
func TestLoadBalancing_E2E(t *testing.T) {
	resetCache()
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-1"))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-2"))
	}))
	defer backend2.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "lb-e2e.test",
		"action": map[string]any{
			"type": "load_balancer",
			"targets": []map[string]any{
				{"url": backend1.URL, "weight": 1},
				{"url": backend2.URL, "weight": 1},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://lb-e2e.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if body != "backend-1" && body != "backend-2" {
		t.Fatalf("expected response from backend-1 or backend-2, got: %s", body)
	}
}

// TestEcho_E2E tests echo action
func TestEcho_E2E(t *testing.T) {
	resetCache()
	cfg := echoOriginJSON(t, "echo.test", nil)

	r := newTestRequest(t, "POST", "http://echo.test/test-path?foo=bar")
	r.Header.Set("X-Custom", "hello")
	w := serveOriginJSON(t, cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse echo response: %v", err)
	}
	req, ok := result["request"].(map[string]any)
	if !ok {
		t.Fatal("echo response missing 'request' object")
	}
	if method, ok := req["method"].(string); !ok || method != "POST" {
		t.Fatalf("expected method POST, got %v", req["method"])
	}
	if urlStr, ok := req["url"].(string); !ok || !strings.Contains(urlStr, "foo=bar") {
		t.Fatalf("expected URL with foo=bar, got %v", req["url"])
	}
}

// TestRetry_E2E tests that proxy action with retry config compiles and runs
func TestRetry_E2E(t *testing.T) {
	resetCache()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	// Verify the retry config compiles successfully
	cfg := originJSON(t, map[string]any{
		"hostname": "retry-e2e.test",
		"action": map[string]any{
			"type": "proxy",
			"url":  backend.URL,
			"retry": map[string]any{
				"count": 2,
			},
		},
	})

	compiled := compileTestOrigin(t, cfg)
	if compiled == nil {
		t.Fatal("expected compiled origin, got nil")
	}
}

// TestCSRF_Protection_E2E tests CSRF token validation
func TestCSRF_Protection_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "csrf.test",
		"action":   map[string]any{"type": "echo"},
		"policies": []map[string]any{
			{
				"type":   "csrf",
				"secret": "cR7tK3mW9pL2vX5qJ8bN4mW6nY!!",
			},
		},
	})

	t.Run("GET request passes without token", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://csrf.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for GET, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("POST without token returns 403", func(t *testing.T) {
		r := newTestRequest(t, "POST", "http://csrf.test/submit")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for POST without CSRF token, got %d", w.Code)
		}
	})
}

// TestRequestBodyTransform_E2E tests request body with modifiers applied
func TestRequestBodyTransform_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "body-transform.test",
		"action":   map[string]any{"type": "echo"},
		"request_modifiers": []map[string]any{
			{
				"headers": map[string]any{
					"add": map[string]string{
						"X-Body-Modified": "true",
					},
				},
			},
		},
	})

	r := newTestRequest(t, "POST", "http://body-transform.test/")
	r.Header.Set("Content-Type", "application/json")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSessionManagement_E2E tests that session config compiles and requests work.
// Without a full SessionProvider, sessions are not persisted but the pipeline still functions.
func TestSessionManagement_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "session-mgmt.test",
		"action":   map[string]any{"type": "echo"},
		"session": map[string]any{
			"cookie_name": "sb_session",
			"ttl":         "1h",
			"http_only":   true,
			"secure":      true,
		},
	})

	r := newTestRequest(t, "GET", "http://session-mgmt.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
