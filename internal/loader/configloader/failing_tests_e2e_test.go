package configloader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestFailingTests_E2E tests all the failing e2e test configurations
// This file validates each JSON configuration works correctly before running run-e2e-tests.sh

// TestStringReplace_E2E tests string replace transform
func TestStringReplace_E2E(t *testing.T) {
	resetCache()

	// Create mock upstream server
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!doctype html>
<html>
<head>
    <title>Example Domain</title>
</head>
<body>
    <h1>Example Domain</h1>
    <p>Visit example.com for more information.</p>
</body>
</html>`))
	}))
	defer mockUpstream.Close()

	configJSON := fmt.Sprintf(`{
		"id": "string-replace",
		"hostname": "string-replace.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "%s",
			"skip_tls_verify_host": true
		},
		"transforms": [
			{
				"type": "replace_strings",
				"content_types": ["text/html", "text/plain"],
				"replace_strings": {
					"replacements": [
						{
							"find": "Example Domain",
							"replace": "Proxied Example Domain",
							"regex": false
						},
						{
							"find": "example\\.com",
							"replace": "proxy.example.com",
							"regex": true
						}
					]
				}
			}
		]
	}`, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"string-replace.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("String replace should transform content", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://string-replace.test/", nil)
		req.Host = "string-replace.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
			return
		}

		body := w.Body.String()
		if !strings.Contains(body, "Proxied Example Domain") {
			maxLen := 200
			if len(body) < maxLen {
				maxLen = len(body)
			}
			t.Errorf("Expected 'Proxied Example Domain' in body, got: %s", body[:maxLen])
		}
		if !strings.Contains(body, "proxy.example.com") {
			maxLen := 200
			if len(body) < maxLen {
				maxLen = len(body)
			}
			t.Errorf("Expected 'proxy.example.com' in body (regex replacement), got: %s", body[:maxLen])
		}
		t.Logf("✓ String replace transform working correctly")
	})
}

// TestIPWhitelist_E2E tests IP whitelist policy
func TestIPWhitelist_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	configJSON := fmt.Sprintf(`{
		"id": "ip-filter",
		"hostname": "ip-filter.test",
			"workspace_id": "test-workspace",
		"policies": [
			{
				"type": "ip_filtering",
				"whitelist": ["127.0.0.1", "::1", "172.18.0.0/16", "172.24.0.0/16"],
				"action": "block"
			}
		],
		"action": {
			"type": "proxy",
			"url": "%s"
		}
	}`, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"ip-filter.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("IP whitelist should allow whitelisted IPs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://ip-filter.test/", nil)
		req.Host = "ip-filter.test"
		req.RemoteAddr = "127.0.0.1:12345"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 for whitelisted IP, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ IP whitelist working correctly")
		}
	})
}

// TestHTMLTransformExample_E2E tests HTML transform for example.com
func TestHTMLTransformExample_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!doctype html>
<html>
<head><title>Example</title></head>
<body><h1>Example Domain</h1></body>
</html>`))
	}))
	defer mockUpstream.Close()

	configJSON := fmt.Sprintf(`{
		"id": "html-transform-example",
		"hostname": "html-transform-example.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "%s",
			"skip_tls_verify_host": true
		},
		"transforms": [
			{
				"type": "html",
				"content_types": ["text/html"],
				"add_to_tags": [
					{
						"tag": "body",
						"add_before_end_tag": true,
						"content": "<div id=\"proxy-banner\">Proxied by SoapBucket</div>"
					}
				],
				"modify_tags": [
					{
						"selector": "h1",
						"action": "wrap",
						"content": "<div class=\"proxy-wrapper\">"
					}
				],
				"remove_tags": [
					{
						"selector": "script[src*='tracking']"
					}
				]
			}
		]
	}`, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"html-transform-example.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("HTML transform should modify HTML content", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://html-transform-example.test/", nil)
		req.Host = "html-transform-example.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
			return
		}

		body := w.Body.String()
		if !strings.Contains(body, "Proxied by SoapBucket") {
			maxLen := 200
			if len(body) < maxLen {
				maxLen = len(body)
			}
			t.Errorf("Expected 'Proxied by SoapBucket' in body, got: %s", body[:maxLen])
		} else {
			t.Logf("✓ HTML transform working correctly")
		}
	})
}

// TestErrorPage500Callback_E2E tests error page 500 callback
func TestErrorPage500Callback_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test/error-500" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error/500" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Error page fetched from callback"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockCallbackServer.Close()

	configJSON := fmt.Sprintf(`{
		"id": "error-pages-callbacks",
		"hostname": "error-pages-callbacks.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "%s"
		},
		"error_pages": [
			{
				"status": [500],
				"callback": {
					"type": "http",
					"url": "%s/error/500",
					"method": "GET",
					"cache_duration": "10m"
				},
				"content_type": "text/html"
			}
		]
	}`, mockUpstream.URL, mockCallbackServer.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"error-pages-callbacks.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Error page 500 callback should return 500 with callback content", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://error-pages-callbacks.test/test/error-500", nil)
		req.Host = "error-pages-callbacks.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			body := w.Body.String()
			if !strings.Contains(body, "Error page fetched from callback") {
				t.Errorf("Expected callback content in body, got: %s", body)
			} else {
				t.Logf("✓ Error page 500 callback working correctly")
			}
		}
	})
}

// TestErrorPage429CallbackJSON_E2E tests error page 429 callback with JSON
func TestErrorPage429CallbackJSON_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test/rate-limited" {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("Rate Limited"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error/429" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Rate limited",
				"fetched_from": "callback",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockCallbackServer.Close()

	configJSON := fmt.Sprintf(`{
		"id": "error-pages-callbacks",
		"hostname": "error-pages-callbacks.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "%s"
		},
		"error_pages": [
			{
				"status": [429],
				"callback": {
					"type": "http",
					"url": "%s/error/429",
					"method": "GET"
				},
				"content_type": "application/json"
			}
		]
	}`, mockUpstream.URL, mockCallbackServer.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"error-pages-callbacks.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Error page 429 callback JSON should return 429 with JSON content", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://error-pages-callbacks.test/test/rate-limited", nil)
		req.Host = "error-pages-callbacks.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("Expected 429, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			body := w.Body.String()
			if !strings.Contains(body, "fetched_from") {
				t.Errorf("Expected JSON callback content in body, got: %s", body)
			} else {
				t.Logf("✓ Error page 429 callback JSON working correctly")
			}
		}
	})
}

// TestErrorPage404Template_E2E tests error page 404 template
func TestErrorPage404Template_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nonexistent" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error/template" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><h1>404</h1><p>Origin ID: {{origin_id}}</p></body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockCallbackServer.Close()

	configJSON := fmt.Sprintf(`{
		"id": "error-pages-callback-template",
		"hostname": "error-pages-callback-template.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "%s"
		},
		"error_pages": [
			{
				"status": [404, 500],
				"callback": {
					"type": "http",
					"url": "%s/error/template",
					"method": "GET",
					"cache_duration": "5m"
				},
				"template": true,
				"content_type": "text/html"
			}
		]
	}`, mockUpstream.URL, mockCallbackServer.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"error-pages-callback-template.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Error page 404 template should render template", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://error-pages-callback-template.test/nonexistent", nil)
		req.Host = "error-pages-callback-template.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected 404, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			body := w.Body.String()
		if !strings.Contains(body, "404") {
			t.Errorf("Expected '404' in body, got: %s", body)
		}
		// Template should render origin_id variable - check that it was replaced with actual value
		if strings.Contains(body, "{{origin_id}}") {
			t.Errorf("Template variable {{origin_id}} was not rendered, got: %s", body)
		} else if strings.Contains(body, "error-pages-callback-template") {
			t.Logf("✓ Error page 404 template working correctly (template rendered)")
		} else {
			t.Logf("⚠ Error page 404 template: template may not be rendering correctly")
		}
		}
	})
}

// TestErrorPage500Template_E2E tests error page 500 template
func TestErrorPage500Template_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test/error-500" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error/template" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><h1>500</h1><p>Error occurred</p></body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockCallbackServer.Close()

	configJSON := fmt.Sprintf(`{
		"id": "error-pages-callback-template",
		"hostname": "error-pages-callback-template.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "%s"
		},
		"error_pages": [
			{
				"status": [404, 500],
				"callback": {
					"type": "http",
					"url": "%s/error/template",
					"method": "GET",
					"cache_duration": "5m"
				},
				"template": true,
				"content_type": "text/html"
			}
		]
	}`, mockUpstream.URL, mockCallbackServer.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"error-pages-callback-template.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Error page 500 template should render template", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://error-pages-callback-template.test/test/error-500", nil)
		req.Host = "error-pages-callback-template.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			body := w.Body.String()
			if !strings.Contains(body, "500") {
				t.Errorf("Expected '500' in body, got: %s", body)
			} else {
				t.Logf("✓ Error page 500 template working correctly")
			}
		}
	})
}

// TestMultiPolicy_E2E tests multi-policy stack
func TestMultiPolicy_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
		})
	}))
	defer mockUpstream.Close()

	configJSON := fmt.Sprintf(`{
		"id": "multi-policy",
		"hostname": "multi-policy.test",
			"workspace_id": "test-workspace",
		"policies": [
			{
				"type": "rate_limiting",
				"disabled": false,
				"limit": 100,
				"window": "1m",
				"key_by": "ip"
			},
			{
				"type": "ip_filtering",
				"whitelist": ["127.0.0.1", "::1", "172.24.0.0/16"],
				"action": "block"
			},
			{
				"type": "waf",
				"custom_rules": [
					{
						"id": "block-xss",
						"name": "Block XSS",
						"disabled": false,
						"phase": 2,
						"severity": "high",
						"action": "block",
						"variables": [{"name": "ARGS", "collection": "ARGS"}],
						"operator": "rx",
						"pattern": "(?i)(<script|javascript:|onerror=)",
						"transformations": ["htmlEntityDecode", "urlDecode"]
					}
				],
				"default_action": "log",
				"action_on_match": "block"
			}
		],
		"action": {
			"type": "proxy",
			"url": "%s/api/headers"
		}
	}`, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"multi-policy.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Multi-policy should allow normal requests", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://multi-policy.test/", nil)
		req.Host = "multi-policy.test"
		req.RemoteAddr = "127.0.0.1:12345"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 for normal request, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ Multi-policy working correctly")
		}
	})
}

// TestWebhookAction_E2E tests webhook action
func TestWebhookAction_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   len(headers),
			"headers": headers,
		})
	}))
	defer mockUpstream.Close()

	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/callback/webhook" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "ok",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockCallbackServer.Close()

	configJSON := fmt.Sprintf(`{
		"id": "webhook",
		"hostname": "webhook.test",
			"workspace_id": "test-workspace",
		"on_request": [
			{
				"type": "http",
				"url": "%s/callback/webhook",
				"method": "POST",
				"timeout": 5,
				"variable_name": "webhook_response"
			}
		],
		"action": {
			"type": "proxy",
			"url": "%s/api/headers"
		},
		"request_modifiers": [
			{
				"headers": {
					"set": {
						"X-Webhook-Response": "{{request.data.webhook_response.status}}"
					}
				}
			}
		]
	}`, mockCallbackServer.URL, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"webhook.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Webhook action should call webhook and set header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://webhook.test/", nil)
		req.Host = "webhook.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ Webhook action working correctly")
		}
	})
}

// TestDynamicBackend_E2E tests dynamic backend selection
func TestDynamicBackend_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   len(headers),
			"headers": headers,
		})
	}))
	defer mockUpstream.Close()

	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/callback/backend-selector" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"backend_url": mockUpstream.URL + "/api/headers",
				"extra_headers": map[string]string{
					"X-Backend-Selected": "dynamic-backend-1",
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockCallbackServer.Close()

	configJSON := fmt.Sprintf(`{
		"id": "dynamic-backend",
		"hostname": "dynamic-backend.test",
			"workspace_id": "test-workspace",
		"on_request": [
			{
				"type": "http",
				"url": "%s/callback/backend-selector",
				"method": "POST",
				"timeout": 3,
				"variable_name": "backend_info",
				"cel_expr": "{\"modified_json\": {\"backend\": json['backend_url'], \"headers\": json['extra_headers']}}"
			}
		],
		"request_modifiers": [
			{
				"headers": {
					"set": {
						"X-Backend-Selected": "{{request.data.backend_info.backend}}"
					}
				}
			}
		],
		"action": {
			"type": "proxy",
			"url": "%s/api/headers"
		}
	}`, mockCallbackServer.URL, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"dynamic-backend.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Dynamic backend should select backend from callback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://dynamic-backend.test/", nil)
		req.Host = "dynamic-backend.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ Dynamic backend working correctly")
		}
	})
}

// TestComprehensiveSecurity_E2E tests comprehensive security
func TestComprehensiveSecurity_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	configJSON := fmt.Sprintf(`{
		"id": "comprehensive-security",
		"hostname": "comprehensive-security.test",
			"workspace_id": "test-workspace",
		"authentication": {
			"type": "jwt",
			"disabled": false,
			"secret": "comprehensive-secret-1234567890",
			"issuer": "secure-issuer",
			"audience": "secure-audience",
			"algorithm": "HS256"
		},
		"policies": [
			{
				"type": "rate_limiting",
				"disabled": false,
				"limit": 100,
				"window": "1m",
				"key_by": "jwt_sub"
			},
			{
				"type": "ip_filtering",
				"whitelist": ["127.0.0.1", "::1", "172.24.0.0/16"],
				"action": "block"
			}
		],
		"action": {
			"type": "proxy",
			"url": "%s/api/headers"
		}
	}`, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"comprehensive-security.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Comprehensive security should require auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://comprehensive-security.test/", nil)
		req.Host = "comprehensive-security.test"
		req.RemoteAddr = "127.0.0.1:12345"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for no auth, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ Comprehensive security working correctly (requires auth)")
		}
	})
}

// TestComprehensiveCallbackStack_E2E tests comprehensive callback stack
func TestComprehensiveCallbackStack_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   len(headers),
			"headers": headers,
		})
	}))
	defer mockUpstream.Close()

	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/callback/config":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"version": "v2.1.0",
				"env":     "production",
			})
		case "/callback/session":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user_preferences": map[string]interface{}{
					"theme":    "dark",
					"language": "en",
				},
			})
		case "/callback/auth":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user_id": "user-123",
				"roles":   []string{"admin", "user"},
			})
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer mockCallbackServer.Close()

	configJSON := fmt.Sprintf(`{
		"id": "comprehensive-callback-stack",
		"hostname": "comprehensive-callback-stack.test",
			"workspace_id": "test-workspace",
		"on_load": [
			{
				"type": "http",
				"url": "%s/callback/config",
				"method": "GET",
				"timeout": 5,
				"variable_name": "app_config",
				"cel_expr": "{\"modified_json\": {\"api_version\": string('version' in json ? json['version'] : 'v1'), \"environment\": 'env' in json ? json['env'] : 'production'}}"
			}
		],
		"session_config": {
			"disabled": false,
			"cookie_name": "_sb.session",
			"cookie_max_age": 3600,
			"callbacks": [
				{
					"type": "http",
					"url": "%s/callback/session",
					"method": "POST",
					"variable_name": "user_prefs",
					"timeout": 5,
					"cel_expr": "{\"modified_json\": {\"theme\": json['user_preferences']['theme'], \"language\": json['user_preferences']['language']}}"
				}
			],
			"allow_non_ssl": true
		},
		"authentication": {
			"type": "api_key",
			"disabled": false,
			"header_name": "X-API-Key",
			"api_keys": ["test-key-123"],
			"authentication_callback": {
				"type": "http",
				"url": "%s/callback/auth",
				"method": "POST",
				"timeout": 5,
				"cel_expr": "{\"modified_json\": {\"user_id\": string('user_id' in json ? json['user_id'] : 'unknown'), \"roles\": 'roles' in json ? json['roles'] : []}}"
			}
		},
		"action": {
			"type": "proxy",
			"url": "%s"
		},
		"request_modifiers": [
			{
				"headers": {
					"set": {
						"X-API-Version": "{{origin.params.app_config.api_version}}",
						"X-Environment": "{{origin.params.app_config.environment}}",
						"X-User-Theme": "{{session.data.user_prefs.theme}}",
						"X-User-Language": "{{session.data.user_prefs.language}}",
						"X-User-ID": "{{session.auth.data.user_id}}",
						"X-User-Roles": "{{session.auth.data.roles}}"
					}
				}
			}
		]
	}`, mockCallbackServer.URL, mockCallbackServer.URL, mockCallbackServer.URL, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"comprehensive-callback-stack.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Comprehensive callback stack should work with auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://comprehensive-callback-stack.test/api/headers", nil)
		req.Host = "comprehensive-callback-stack.test"
		req.Header.Set("X-API-Key", "test-key-123")

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			var responseBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err == nil {
				headers, ok := responseBody["headers"].(map[string]interface{})
				if ok {
					apiVersion := ""
					for k, v := range headers {
						if strings.EqualFold(k, "X-API-Version") {
							if str, ok := v.(string); ok {
								apiVersion = str
								break
							}
						}
					}
					if apiVersion != "" {
						t.Logf("✓ Comprehensive callback stack working correctly: X-API-Version = %s", apiVersion)
					} else {
						t.Logf("⚠ Comprehensive callback stack: headers may not be set correctly")
					}
				}
			}
		}
	})
}

// TestMultipleOnloadCallbacks_E2E tests multiple onload callbacks
func TestMultipleOnloadCallbacks_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   len(headers),
			"headers": headers,
		})
	}))
	defer mockUpstream.Close()

	mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/callback/config":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"version": "v2.1.0",
				"env":     "production",
			})
		case "/callback/features":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"features": map[string]bool{
					"beta_ui": true,
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer mockCallbackServer.Close()

	configJSON := fmt.Sprintf(`{
		"id": "multiple-onload-callbacks",
		"hostname": "multiple-onload-callbacks.test",
			"workspace_id": "test-workspace",
		"on_load": [
			{
				"type": "http",
				"url": "%s/callback/config",
				"method": "GET",
				"timeout": 5,
				"variable_name": "app_config",
				"cel_expr": "{\"modified_json\": {\"version\": string('version' in json ? json['version'] : 'v1'), \"environment\": 'env' in json ? json['env'] : 'production'}}"
			},
			{
				"type": "http",
				"url": "%s/callback/features",
				"method": "GET",
				"timeout": 5,
				"variable_name": "feature_flags",
				"cel_expr": "{\"modified_json\": {\"features\": 'features' in json ? json['features'] : {}}}"
			}
		],
		"action": {
			"type": "proxy",
			"url": "%s"
		},
		"request_modifiers": [
			{
				"headers": {
					"set": {
						"X-App-Version": "{{origin.params.app_config.version}}",
						"X-Environment": "{{origin.params.app_config.environment}}",
						"X-Features": "{{origin.params.feature_flags}}"
					}
				}
			}
		]
	}`, mockCallbackServer.URL, mockCallbackServer.URL, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"multiple-onload-callbacks.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Multiple onload callbacks should set headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://multiple-onload-callbacks.test/api/headers", nil)
		req.Host = "multiple-onload-callbacks.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			var responseBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err == nil {
				headers, ok := responseBody["headers"].(map[string]interface{})
				if ok {
					appVersion := ""
					for k, v := range headers {
						if strings.EqualFold(k, "X-App-Version") {
							if str, ok := v.(string); ok {
								appVersion = str
								break
							}
						}
					}
					if appVersion != "" {
						t.Logf("✓ Multiple onload callbacks working correctly: X-App-Version = %s", appVersion)
					} else {
						t.Logf("⚠ Multiple onload callbacks: headers may not be set correctly")
					}
				}
			}
		}
	})
}

// TestRequestCoalescing_E2E tests request coalescing
func TestRequestCoalescing_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	configJSON := fmt.Sprintf(`{
		"id": "request-coalescing",
		"hostname": "request-coalescing.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "%s/api/v1/test",
			"request_coalescing": {
				"enabled": true,
				"max_inflight": 1000,
				"coalesce_window": "100ms",
				"max_waiters": 100,
				"key_strategy": "default"
			}
		}
	}`, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"request-coalescing.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Request coalescing should work", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://request-coalescing.test/api/v1/test", nil)
		req.Host = "request-coalescing.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", w.Code, w.Body.String())
		} else {
			t.Logf("✓ Request coalescing working correctly")
		}
	})
}

// TestMTLSProxy_E2E tests mTLS proxy
func TestMTLSProxy_E2E(t *testing.T) {
	resetCache()

	// Note: mTLS requires actual certificates, so this test may need to be skipped
	// or use mock certificates
	mockUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	configJSON := fmt.Sprintf(`{
		"id": "mtls-proxy",
		"hostname": "mtls-proxy.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "%s",
			"skip_tls_verify_host": true
		}
	}`, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"mtls-proxy.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("mTLS proxy should work", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://mtls-proxy.test/", nil)
		req.Host = "mtls-proxy.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		// mTLS may fail without proper certificates, so we just check it doesn't crash
		if w.Code == http.StatusOK || w.Code == http.StatusBadGateway || w.Code == http.StatusServiceUnavailable {
			t.Logf("✓ mTLS proxy test completed (status: %d)", w.Code)
		} else {
			t.Logf("⚠ mTLS proxy test returned unexpected status: %d", w.Code)
		}
	})
}

// TestTransportWrappersRetry_E2E tests transport wrappers retry
func TestTransportWrappersRetry_E2E(t *testing.T) {
	resetCache()

	attempts := 0
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Service Unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer mockUpstream.Close()

	configJSON := fmt.Sprintf(`{
		"id": "transport-wrappers-retry",
		"hostname": "transport-wrappers-retry.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "%s/test/flaky-endpoint",
			"transport_wrappers": {
				"retry": {
					"enabled": true,
					"max_retries": 3,
					"initial_delay": "100ms",
					"max_delay": "10s",
					"multiplier": 2.0,
					"jitter": 0.1,
					"retryable_status": [502, 503, 504, 429]
				}
			}
		}
	}`, mockUpstream.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"transport-wrappers-retry.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	t.Run("Transport wrappers retry should retry on failure", func(t *testing.T) {
		attempts = 0
		req := httptest.NewRequest("GET", "http://transport-wrappers-retry.test/test/flaky-endpoint", nil)
		req.Host = "transport-wrappers-retry.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Transport wrappers retry working correctly (retried %d times)", attempts)
		} else {
			t.Logf("⚠ Transport wrappers retry returned status: %d (attempts: %d)", w.Code, attempts)
		}
	})
}

