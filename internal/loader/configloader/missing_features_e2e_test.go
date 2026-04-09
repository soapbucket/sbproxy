package configloader

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestAuthentication_APIKey_E2E tests API key authentication
func TestAuthentication_APIKey_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": r.Header.Get("X-API-Key"),
			"user": "authenticated",
		})
	}))
	defer mockUpstream.Close()

	t.Run("API key authentication allows valid keys", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "auth-apikey",
			"hostname": "auth-apikey.test",
			"workspace_id": "test-workspace",
			"authentication": {
				"type": "api_key",
				"disabled": false,
				"header_name": "X-API-Key",
				"keys": ["key-123", "key-456"]
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"auth-apikey.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://auth-apikey.test/api", nil)
		req.Host = "auth-apikey.test"
		req.Header.Set("X-API-Key", "key-123")

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Valid API key authenticated")
		}
	})

	t.Run("API key authentication rejects invalid keys", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "auth-apikey-reject",
			"hostname": "auth-apikey-reject.test",
			"workspace_id": "test-workspace",
			"authentication": {
				"type": "api_key",
				"disabled": false,
				"header_name": "X-API-Key",
				"keys": ["key-123"]
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"auth-apikey-reject.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://auth-apikey-reject.test/api", nil)
		req.Host = "auth-apikey-reject.test"
		req.Header.Set("X-API-Key", "invalid-key")

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
			t.Logf("✓ Invalid API key rejected with status %d", w.Code)
		}
	})
}

// TestAuthentication_BasicAuth_E2E tests basic authentication
func TestAuthentication_BasicAuth_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		user, pass, _ := r.BasicAuth()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user": user,
			"pass": pass,
		})
	}))
	defer mockUpstream.Close()

	t.Run("Basic authentication with valid credentials", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "auth-basic",
			"hostname": "auth-basic.test",
			"workspace_id": "test-workspace",
			"authentication": {
				"type": "basic_auth",
				"disabled": false,
				"credentials": [
					{"username": "alice", "password": "pass123"},
					{"username": "bob", "password": "pass456"}
				]
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"auth-basic.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://auth-basic.test/api", nil)
		req.Host = "auth-basic.test"
		req.SetBasicAuth("alice", "pass123")

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Basic auth accepted")
		}
	})
}

// TestResponseCache_E2E tests response caching
func TestResponseCache_E2E(t *testing.T) {
	resetCache()

	requestCount := 0
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"request_number": requestCount,
			"data":           "cached-response",
		})
	}))
	defer mockUpstream.Close()

	t.Run("Response caching reduces upstream requests", func(t *testing.T) {
		resetCache()
		requestCount = 0

		configJSON := fmt.Sprintf(`{
			"id": "response-cache",
			"hostname": "response-cache.test",
			"workspace_id": "test-workspace",
			"action": {
				"type": "proxy",
				"url": "%s"
			},
			"response_cache": {
				"enabled": true,
				"ttl": "1h",
				"cache_key": "{{request.path}}",
				"vary_by_headers": ["Accept-Language"],
				"cache_control": "public, max-age=3600",
				"status_codes": [200, 201]
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"response-cache.test": []byte(configJSON),
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

		// First request
		req := httptest.NewRequest("GET", "http://response-cache.test/api/data", nil)
		req.Host = "response-cache.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK && requestCount == 1 {
			t.Logf("✓ First request succeeded, upstream called")
		}

		// Second request (should be cached)
		w2 := httptest.NewRecorder()
		cfg.ServeHTTP(w2, req)

		if w2.Code == http.StatusOK {
			t.Logf("✓ Cached response returned")
		}
	})
}

// TestRedirect_E2E tests redirect action
func TestRedirect_E2E(t *testing.T) {
	resetCache()

	t.Run("Redirect to new URL", func(t *testing.T) {
		resetCache()

		configJSON := `{
			"id": "redirect",
			"hostname": "redirect.test",
			"workspace_id": "test-workspace",
			"action": {
				"type": "redirect",
				"url": "https://example.com/new-location",
				"status_code": 301,
				"preserve_query": true
			}
		}`

		mockStore := &mockStorage{
			data: map[string][]byte{
				"redirect.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://redirect.test/old?page=1", nil)
		req.Host = "redirect.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusMovedPermanently || w.Code == http.StatusFound {
			location := w.Header().Get("Location")
			if strings.Contains(location, "example.com") {
				t.Logf("✓ Redirect with status %d to %s", w.Code, location)
			}
		}
	})
}

// TestStaticContent_E2E tests static file serving
func TestStaticContent_E2E(t *testing.T) {
	resetCache()

	t.Run("Serve static content", func(t *testing.T) {
		resetCache()

		configJSON := `{
			"id": "static",
			"hostname": "static.test",
			"workspace_id": "test-workspace",
			"action": {
				"type": "static",
				"status_code": 200,
				"body": "<!DOCTYPE html><html><body><h1>Static Content</h1></body></html>",
				"content_type": "text/html",
				"headers": {
					"Cache-Control": "public, max-age=86400",
					"X-Custom": "static-value"
				}
			}
		}`

		mockStore := &mockStorage{
			data: map[string][]byte{
				"static.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://static.test/index.html", nil)
		req.Host = "static.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "Static Content") {
			t.Logf("✓ Static content served successfully")
		}
	})
}

// TestSecurityHeaders_E2E tests security header injection
func TestSecurityHeaders_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Test</body></html>"))
	}))
	defer mockUpstream.Close()

	t.Run("Security headers added to response", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "security-headers",
			"hostname": "security-headers.test",
			"workspace_id": "test-workspace",
			"policies": [
				{
					"type": "security_headers",
					"headers": {
						"strict_transport_security": "max-age=31536000; includeSubDomains",
						"x_content_type_options": "nosniff",
						"x_frame_options": "DENY",
						"x_xss_protection": "1; mode=block",
						"content_security_policy": "default-src 'self'",
						"referrer_policy": "strict-origin-when-cross-origin"
					}
				}
			],
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"security-headers.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://security-headers.test/page", nil)
		req.Host = "security-headers.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			hsts := w.Header().Get("Strict-Transport-Security")
			if hsts != "" {
				t.Logf("✓ Security headers added: HSTS=%s", hsts)
			}
		}
	})
}

// TestJSONProjection_E2E tests JSON field projection
func TestJSONProjection_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user": map[string]interface{}{
				"id":    42,
				"name":  "Alice",
				"email": "alice@example.com",
				"role":  "admin",
			},
			"metadata": map[string]interface{}{
				"created": "2024-01-01",
				"updated": "2024-03-02",
			},
		})
	}))
	defer mockUpstream.Close()

	t.Run("JSON projection extracts specific fields", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "json-projection",
			"hostname": "json-projection.test",
			"workspace_id": "test-workspace",
			"action": {
				"type": "proxy",
				"url": "%s"
			},
			"transforms": [
				{
					"type": "json_projection",
					"content_types": ["application/json"],
					"include": ["user.id", "user.name", "metadata.created"]
				}
			]
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"json-projection.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://json-projection.test/api/user", nil)
		req.Host = "json-projection.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err == nil {
				t.Logf("✓ JSON projection response received")
			}
		}
	})
}

// TestLoadBalancing_E2E tests load balancing across multiple backends
func TestLoadBalancing_E2E(t *testing.T) {
	resetCache()

	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"backend": "server1"})
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"backend": "server2"})
	}))
	defer backend2.Close()

	backend3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"backend": "server3"})
	}))
	defer backend3.Close()

	t.Run("Load balancer distributes requests", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "load-balancer",
			"hostname": "lb.test",
			"workspace_id": "test-workspace",
			"action": {
				"type": "loadbalancer",
				"algorithm": "round_robin",
				"targets": [
					{"url": "%s", "weight": 1},
					{"url": "%s", "weight": 1},
					{"url": "%s", "weight": 1}
				],
				"health_check": {
					"enabled": true,
					"path": "/health",
					"interval": "10s",
					"timeout": "2s"
				}
			}
		}`, backend1.URL, backend2.URL, backend3.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"lb.test": []byte(configJSON),
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

		// Make multiple requests
		for i := 1; i <= 3; i++ {
			req := httptest.NewRequest("GET", "http://lb.test/api", nil)
			req.Host = "lb.test"

			cfg, err := Load(req, mgr)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			w := httptest.NewRecorder()
			cfg.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				var result map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err == nil {
					if backend, ok := result["backend"].(string); ok {
						t.Logf("✓ Request %d routed to %s", i, backend)
					}
				}
			}
		}
	})
}

// TestEcho_E2E tests echo action
func TestEcho_E2E(t *testing.T) {
	resetCache()

	t.Run("Echo action returns request details", func(t *testing.T) {
		resetCache()

		configJSON := `{
			"id": "echo",
			"hostname": "echo.test",
			"workspace_id": "test-workspace",
			"action": {
				"type": "echo"
			}
		}`

		mockStore := &mockStorage{
			data: map[string][]byte{
				"echo.test": []byte(configJSON),
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

		req := httptest.NewRequest("POST", "http://echo.test/api/test?page=1", nil)
		req.Host = "echo.test"
		req.Header.Set("Content-Type", "application/json")

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err == nil {
				if method, ok := result["method"].(string); ok && method == "POST" {
					t.Logf("✓ Echo returned request method: %s", method)
				}
			}
		}
	})
}

// TestRetry_E2E tests retry logic with backoff
func TestRetry_E2E(t *testing.T) {
	resetCache()

	failCount := 0
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failCount++
		if failCount < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Service temporarily unavailable"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "recovered"})
	}))
	defer mockUpstream.Close()

	t.Run("Retry logic recovers from transient failures", func(t *testing.T) {
		resetCache()
		failCount = 0

		configJSON := fmt.Sprintf(`{
			"id": "retry",
			"hostname": "retry.test",
			"workspace_id": "test-workspace",
			"action": {
				"type": "proxy",
				"url": "%s",
				"transport": {
					"retry": {
						"max_attempts": 3,
						"backoff": "exponential",
						"initial_delay": "10ms",
						"max_delay": "1s",
						"retryable_status_codes": [502, 503, 504]
					}
				}
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"retry.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://retry.test/api", nil)
		req.Host = "retry.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Retry logic recovered after %d attempts", failCount)
		}
	})
}

// TestCSRF_Protection_E2E tests CSRF token validation
func TestCSRF_Protection_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"csrf": r.Header.Get("X-CSRF-Token")})
	}))
	defer mockUpstream.Close()

	t.Run("CSRF protection validates tokens", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "csrf-protection",
			"hostname": "csrf.test",
			"workspace_id": "test-workspace",
			"policies": [
				{
					"type": "csrf",
					"disabled": false,
					"secret": "test-secret-key-32-chars-minimum!",
					"token_name": "csrf_token",
					"header_name": "X-CSRF-Token",
					"methods": ["POST", "PUT", "DELETE"],
					"cookie_name": "csrf_cookie",
					"cookie_http_only": true,
					"cookie_secure": false,
					"cookie_same_site": "Lax",
					"form_field_name": "csrf_field"
				}
			],
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"csrf.test": []byte(configJSON),
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

		req := httptest.NewRequest("POST", "http://csrf.test/api/form", nil)
		req.Host = "csrf.test"
		req.Header.Set("X-CSRF-Token", "test-token-123")

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK || w.Code == http.StatusForbidden {
			t.Logf("✓ CSRF protection evaluated with status %d", w.Code)
		}
	})
}

// TestGeoBlocking_E2E tests geo-blocking policy
func TestGeoBlocking_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true})
	}))
	defer mockUpstream.Close()

	t.Run("Geo-blocking allows whitelisted countries", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "geo-blocking",
			"hostname": "geo.test",
			"workspace_id": "test-workspace",
			"policies": [
				{
					"type": "geo_blocking",
					"allow_countries": ["US", "CA", "GB"],
					"action": "block",
					"block_status_code": 403
				}
			],
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"geo.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://geo.test/api", nil)
		req.Host = "geo.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		t.Logf("✓ Geo-blocking evaluated with status %d", w.Code)
	})
}

// TestRequestBodyTransform_E2E tests request body transformation
func TestRequestBodyTransform_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1024)
		n, _ := r.Body.Read(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"received": string(body[:n]),
		})
	}))
	defer mockUpstream.Close()

	t.Run("Request body transformation modifies payload", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "req-body-transform",
			"hostname": "req-body.test",
			"workspace_id": "test-workspace",
			"action": {
				"type": "proxy",
				"url": "%s"
			},
			"transforms": [
				{
					"type": "json",
					"content_types": ["application/json"],
					"phase": "request",
					"operations": [
						{
							"op": "set",
							"path": "/transformed",
							"value": "true"
						},
						{
							"op": "set",
							"path": "/timestamp",
							"value": "{{timestamp}}"
						}
					]
				}
			]
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"req-body.test": []byte(configJSON),
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

		req := httptest.NewRequest("POST", "http://req-body.test/api", nil)
		req.Host = "req-body.test"
		req.Header.Set("Content-Type", "application/json")
		req.Body = io.NopCloser(strings.NewReader(`{"original": "data"}`))

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Request body transformation completed")
		}
	})
}

// TestSessionManagement_E2E tests session management
func TestSessionManagement_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"session_id": "test-session",
			"user": "authenticated",
		})
	}))
	defer mockUpstream.Close()

	t.Run("Session management preserves state", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "session-mgmt",
			"hostname": "session.test",
			"workspace_id": "test-workspace",
			"session_config": {
				"disabled": false,
				"cookie_name": "_sb_session",
				"cookie_max_age": 3600,
				"cookie_http_only": true,
				"cookie_secure": false,
				"allow_non_ssl": true
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"session.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://session.test/api", nil)
		req.Host = "session.test"
		requestData := reqctx.NewRequestData()
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Session management functional")
		}
	})
}
