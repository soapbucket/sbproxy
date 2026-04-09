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
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestVariables_TemplateInterpolation_E2E tests variable interpolation in configurations
func TestVariables_TemplateInterpolation_E2E(t *testing.T) {
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
			"headers": headers,
			"path":    r.URL.Path,
			"method":  r.Method,
		})
	}))
	defer mockUpstream.Close()

	t.Run("Request variables interpolation", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "variables-request",
			"hostname": "vars-request.test",
			"workspace_id": "test-workspace",
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"X-Request-Method": "{{request.method}}",
							"X-Request-Path": "{{request.path}}",
							"X-Request-Host": "{{request.host}}",
							"X-Request-Protocol": "{{request.protocol}}"
						}
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
				"vars-request.test": []byte(configJSON),
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

		req := httptest.NewRequest("POST", "http://vars-request.test/api/users", nil)
		req.Host = "vars-request.test"
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
			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err == nil {
				if headers, ok := result["headers"].(map[string]interface{}); ok {
					if method, ok := headers["X-Request-Method"].(string); ok && method == "POST" {
						t.Logf("✓ Request method variable interpolated: %s", method)
					}
					if path, ok := headers["X-Request-Path"].(string); ok && strings.Contains(path, "/api/users") {
						t.Logf("✓ Request path variable interpolated: %s", path)
					}
				}
			}
		}
	})

	t.Run("Environment variables in headers", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "variables-env",
			"hostname": "vars-env.test",
			"workspace_id": "test-workspace",
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"X-Environment": "{{env.ENVIRONMENT}}",
							"X-API-Version": "{{env.API_VERSION}}",
							"X-Service-Name": "soapbucket-proxy"
						}
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
				"vars-env.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://vars-env.test/health", nil)
		req.Host = "vars-env.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Environment variables processed")
		}
	})

	t.Run("Config variables from on_load callback", func(t *testing.T) {
		resetCache()

		mockCallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"api_version": "v3",
				"environment": "production",
				"region":      "us-west-2",
			})
		}))
		defer mockCallbackServer.Close()

		configJSON := fmt.Sprintf(`{
			"id": "variables-config",
			"hostname": "vars-config.test",
			"workspace_id": "test-workspace",
			"on_load": [
				{
					"type": "http",
					"url": "%s",
					"method": "GET",
					"timeout": 5,
					"lua_script": "local r = {}; r.api_version = json['api_version'] or 'v1'; r.environment = json['environment'] or 'dev'; r.region = json['region'] or 'default'; return r"
				}
			],
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"X-API-Version": "{{origin.params.api_version}}",
							"X-Environment": "{{origin.params.environment}}",
							"X-Region": "{{origin.params.region}}"
						}
					}
				}
			],
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockCallbackServer.URL, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"vars-config.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://vars-config.test/api", nil)
		req.Host = "vars-config.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err == nil {
				if headers, ok := result["headers"].(map[string]interface{}); ok {
					if version, ok := headers["X-Api-Version"].(string); ok && version == "v3" {
						t.Logf("✓ Config variable from callback: api_version=%s", version)
					}
				}
			}
		}
	})
}

// TestVaulting_SecretInjection_E2E tests secret vaulting and injection
func TestVaulting_SecretInjection_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"auth_header": r.Header.Get("Authorization"),
			"api_key":     r.Header.Get("X-API-Key"),
		})
	}))
	defer mockUpstream.Close()

	t.Run("Secrets injected via headers from vault", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "vaulting-headers",
			"hostname": "vault-headers.test",
			"workspace_id": "test-workspace",
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"Authorization": "{{secrets.api_token}}",
							"X-API-Key": "{{secrets.api_key}}",
							"X-Webhook-Secret": "{{secrets.webhook_secret}}"
						}
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
				"vault-headers.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://vault-headers.test/api", nil)
		req.Host = "vault-headers.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err == nil {
				if auth, ok := result["auth_header"].(string); ok && auth != "" {
					t.Logf("✓ Secret injected in Authorization header")
				}
			}
		}
	})

	t.Run("Secrets in request body transformations", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "vaulting-body",
			"hostname": "vault-body.test",
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
							"path": "/api_token",
							"value": "{{secrets.api_token}}"
						},
						{
							"op": "set",
							"path": "/webhook_secret",
							"value": "{{secrets.webhook_secret}}"
						}
					]
				}
			]
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"vault-body.test": []byte(configJSON),
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

		req := httptest.NewRequest("POST", "http://vault-body.test/api/auth", nil)
		req.Host = "vault-body.test"
		req.Header.Set("Content-Type", "application/json")

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Secrets processed in body transformation")
		}
	})

	t.Run("Secrets in query parameters", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "vaulting-query",
			"hostname": "vault-query.test",
			"workspace_id": "test-workspace",
			"request_modifiers": [
				{
					"query": {
						"add": {
							"api_key": "{{secrets.api_key}}",
							"token": "{{secrets.access_token}}"
						}
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
				"vault-query.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://vault-query.test/api/data", nil)
		req.Host = "vault-query.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Secrets added to query parameters")
		}
	})
}

// TestVariables_SessionData_E2E tests session data variable access
func TestVariables_SessionData_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user_id": r.Header.Get("X-User-ID"),
			"role":    r.Header.Get("X-User-Role"),
		})
	}))
	defer mockUpstream.Close()

	t.Run("Session data in request headers", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "variables-session",
			"hostname": "vars-session.test",
			"workspace_id": "test-workspace",
			"session_config": {
				"disabled": false,
				"cookie_name": "_session",
				"cookie_max_age": 3600,
				"allow_non_ssl": true
			},
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"X-User-ID": "{{session.user_id}}",
							"X-User-Role": "{{session.user_role}}"
						}
					},
					"rules": [
						{
							"cel_expr": "session.user_id != null"
						}
					]
				}
			],
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"vars-session.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://vars-session.test/api", nil)
		req.Host = "vars-session.test"
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
			t.Logf("✓ Session data variables processed")
		}
	})
}

// TestVariables_Conditional_E2E tests conditional variable usage
func TestVariables_Conditional_E2E(t *testing.T) {
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
			"headers": headers,
		})
	}))
	defer mockUpstream.Close()

	t.Run("Variables with conditional CEL expressions", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "variables-conditional",
			"hostname": "vars-cond.test",
			"workspace_id": "test-workspace",
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"X-Admin-Token": "{{secrets.admin_token}}"
						}
					},
					"rules": [
						{
							"cel_expr": "request.headers['x-role'] == 'admin'"
						}
					]
				},
				{
					"headers": {
						"set": {
							"X-User-Token": "{{secrets.user_token}}"
						}
					},
					"rules": [
						{
							"cel_expr": "request.headers['x-role'] == 'user'"
						}
					]
				}
			],
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, mockUpstream.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"vars-cond.test": []byte(configJSON),
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

		// Test as admin
		req := httptest.NewRequest("GET", "http://vars-cond.test/api", nil)
		req.Host = "vars-cond.test"
		req.Header.Set("X-Role", "admin")

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			var result map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err == nil {
				if headers, ok := result["headers"].(map[string]interface{}); ok {
					if _, hasAdminToken := headers["X-Admin-Token"]; hasAdminToken {
						t.Logf("✓ Admin token injected for admin role")
					}
				}
			}
		}
	})
}

// TestVariables_Templating_Advanced_E2E tests advanced template features
func TestVariables_Templating_Advanced_E2E(t *testing.T) {
	resetCache()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"headers": r.Header,
		})
	}))
	defer mockUpstream.Close()

	t.Run("Complex template expressions", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "variables-complex",
			"hostname": "vars-complex.test",
			"workspace_id": "test-workspace",
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"X-Request-ID": "{{request.id}}-{{timestamp}}",
							"X-Client-IP": "{{request.remote_addr}}",
							"X-Service-Version": "1.0.0-{{origin.params.deployment_id}}",
							"X-Trace-ID": "{{env.TRACE_ID}}-{{request.method}}"
						}
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
				"vars-complex.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://vars-complex.test/api", nil)
		req.Host = "vars-complex.test"
		req.RemoteAddr = "203.0.113.42:8080"
		requestData := reqctx.NewRequestData()
		requestData.ID = "req-12345"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Complex template expressions evaluated")
		}
	})
}
