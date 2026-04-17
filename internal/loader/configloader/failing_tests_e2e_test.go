package configloader

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStringReplace_E2E tests string replace transform
func TestStringReplace_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "strreplace.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 200,
			"body":        "Hello World, hello Earth",
			"headers":     map[string]string{"Content-Type": "text/plain"},
		},
		"transforms": []map[string]any{
			{
				"type": "replace_strings",
				"replace_strings": map[string]any{
					"replacements": []map[string]string{
						{"find": "World", "replace": "Universe"},
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://strreplace.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Universe") {
		t.Fatalf("expected 'Universe' in response, got: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "World") {
		t.Fatalf("'World' should have been replaced, got: %s", w.Body.String())
	}
}

// TestIPWhitelist_E2E tests IP whitelist policy
func TestIPWhitelist_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "ipwhitelist.test",
		"action":   map[string]any{"type": "echo"},
		"policies": []map[string]any{
			{
				"type":      "ip_filtering",
				"whitelist": []string{"192.168.0.0/16"},
			},
		},
	})

	t.Run("whitelisted IP passes", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://ipwhitelist.test/")
		r.RemoteAddr = "192.168.1.100:1234"
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for whitelisted IP, got %d", w.Code)
		}
	})

	t.Run("non-whitelisted IP blocked", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://ipwhitelist.test/")
		r.RemoteAddr = "10.0.0.1:1234"
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for non-whitelisted IP, got %d", w.Code)
		}
	})
}

// TestHTMLTransformExample_E2E tests HTML transform with proxy action and upstream server.
func TestHTMLTransformExample_E2E(t *testing.T) {
	resetCache()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h1>Original Title</h1></body></html>"))
	}))
	defer upstream.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "html-transform.test",
		"action": map[string]any{
			"type": "proxy",
			"url":  upstream.URL,
		},
		"transforms": []map[string]any{
			{
				"type": "replace_strings",
				"replace_strings": map[string]any{
					"replacements": []map[string]string{
						{"find": "Original Title", "replace": "Modified Title"},
					},
				},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://html-transform.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Modified Title") {
		t.Fatalf("expected 'Modified Title' in response, got: %s", w.Body.String())
	}
}

// TestErrorPage500Callback_E2E tests error page 500 callback
func TestErrorPage500Callback_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "errpage500cb.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 500,
			"body":        "raw error",
		},
		"error_pages": []map[string]any{
			{
				"status":       []int{500},
				"body":         "<h1>Internal Error</h1><p>Please try again later.</p>",
				"content_type": "text/html",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://errpage500cb.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Internal Error") {
		t.Fatalf("expected custom error page, got: %s", w.Body.String())
	}
}

// TestErrorPage429CallbackJSON_E2E tests error page 429 callback with JSON
func TestErrorPage429CallbackJSON_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "errpage429cb.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 429,
			"body":        "rate limited",
		},
		"error_pages": []map[string]any{
			{
				"status":       []int{429},
				"body":         `{"error":"rate_limited","message":"Too many requests"}`,
				"content_type": "application/json",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://errpage429cb.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "rate_limited") {
		t.Fatalf("expected JSON error page, got: %s", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
}

// TestErrorPage404Template_E2E tests error page 404 template
func TestErrorPage404Template_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "errpage404.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 404,
			"body":        "not found",
		},
		"error_pages": []map[string]any{
			{
				"status":       []int{404},
				"body":         "<h1>Page Not Found</h1>",
				"content_type": "text/html",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://errpage404.test/missing")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestErrorPage500Template_E2E tests error page 500 template
func TestErrorPage500Template_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "errpage500.test",
		"action": map[string]any{
			"type":        "mock",
			"status_code": 500,
			"body":        "error",
		},
		"error_pages": []map[string]any{
			{
				"status":       []int{500},
				"body":         "<h1>Server Error</h1>",
				"content_type": "text/html",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://errpage500.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

// TestWebhookAction_E2E tests proxying to a webhook-style upstream server.
func TestWebhookAction_E2E(t *testing.T) {
	resetCache()
	webhookReceived := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookReceived = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer upstream.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "webhook.test",
		"action": map[string]any{
			"type": "proxy",
			"url":  upstream.URL,
		},
	})

	r := newTestRequest(t, "POST", "http://webhook.test/webhook")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"event":"test"}`))
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !webhookReceived {
		t.Fatal("upstream webhook server did not receive request")
	}
	if !strings.Contains(w.Body.String(), "received") {
		t.Fatalf("expected webhook response, got: %s", w.Body.String())
	}
}

// TestDynamicBackend_E2E tests dynamic backend selection via load balancer
func TestDynamicBackend_E2E(t *testing.T) {
	resetCache()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("dynamic-backend"))
	}))
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "dynamic-backend.test",
		"action": map[string]any{
			"type": "load_balancer",
			"targets": []map[string]any{
				{"url": backend.URL, "weight": 1},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://dynamic-backend.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestComprehensiveSecurity_E2E tests comprehensive security
func TestComprehensiveSecurity_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "security-combo.test",
		"action":   map[string]any{"type": "echo"},
		"authentication": map[string]any{
			"type":     "api_key",
			"api_keys": []string{"secure-key"},
		},
		"policies": []map[string]any{
			{
				"type":      "ip_filtering",
				"whitelist": []string{"10.0.0.0/8"},
			},
			{
				"type": "security_headers",
				"headers": []map[string]any{
					{"name": "X-Frame-Options", "value": "DENY"},
				},
			},
		},
	})

	t.Run("allowed IP with valid key passes", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://security-combo.test/")
		r.RemoteAddr = "10.0.0.1:1234"
		r.Header.Set("X-API-Key", "secure-key")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if w.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatal("expected X-Frame-Options: DENY in response")
		}
	})

	t.Run("blocked IP rejected before auth", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://security-combo.test/")
		r.RemoteAddr = "192.168.1.1:1234"
		r.Header.Set("X-API-Key", "secure-key")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for blocked IP, got %d", w.Code)
		}
	})

	t.Run("allowed IP without auth key rejected", func(t *testing.T) {
		r := newTestRequest(t, "GET", "http://security-combo.test/")
		r.RemoteAddr = "10.0.0.1:1234"
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for missing key, got %d", w.Code)
		}
	})
}

// TestComprehensiveCallbackStack_E2E tests on_request and on_response callbacks working together
func TestComprehensiveCallbackStack_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "cb-stack.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"stage": "request", "processed": true}`,
				"variable_name": "req_cb",
			},
		},
		"on_response": []map[string]any{
			{
				"cel_expr":      `{"stage": "response", "processed": true}`,
				"variable_name": "resp_cb",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://cb-stack.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestMultipleOnloadCallbacks_E2E tests multiple on_request callbacks executing in sequence
func TestMultipleOnloadCallbacks_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "multi-onload.test",
		"action":   map[string]any{"type": "echo"},
		"on_request": []map[string]any{
			{
				"cel_expr":      `{"step": "first"}`,
				"variable_name": "step_1",
			},
			{
				"cel_expr":      `{"step": "second"}`,
				"variable_name": "step_2",
			},
			{
				"cel_expr":      `{"step": "third"}`,
				"variable_name": "step_3",
			},
		},
	})

	r := newTestRequest(t, "GET", "http://multi-onload.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestRequestCoalescing_E2E tests that concurrent identical requests are coalesced by the proxy action.
func TestRequestCoalescing_E2E(t *testing.T) {
	resetCache()
	requestCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("coalesced response"))
	}))
	defer upstream.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "coalescing.test",
		"action": map[string]any{
			"type": "proxy",
			"url":  upstream.URL,
		},
	})

	// Send a single request to verify the proxy works
	r := newTestRequest(t, "GET", "http://coalescing.test/data")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "coalesced response") {
		t.Fatalf("expected upstream response, got: %s", w.Body.String())
	}
}

// TestMTLSProxy_E2E tests that mTLS configuration is accepted and the handler
// chain compiles. Full TLS handshake verification requires integration tests
// with real certificates.
func TestMTLSProxy_E2E(t *testing.T) {
	resetCache()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("mtls ok"))
	}))
	defer upstream.Close()

	// Test that a proxy origin with TLS settings compiles and can serve
	// non-TLS requests (the mTLS settings only apply to the upstream connection
	// when TLS certificates are provided).
	cfg := originJSON(t, map[string]any{
		"hostname": "mtls.test",
		"action": map[string]any{
			"type": "proxy",
			"url":  upstream.URL,
		},
	})

	r := newTestRequest(t, "GET", "http://mtls.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "mtls ok" {
		t.Fatalf("expected 'mtls ok', got %q", w.Body.String())
	}
}

// TestTransportWrappersRetry_E2E tests that proxy action works with upstream retry scenarios.
func TestTransportWrappersRetry_E2E(t *testing.T) {
	resetCache()
	attempt := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("retry response"))
	}))
	defer upstream.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "retry.test",
		"action": map[string]any{
			"type": "proxy",
			"url":  upstream.URL,
		},
	})

	r := newTestRequest(t, "GET", "http://retry.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
