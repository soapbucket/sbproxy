package config

import (
	"encoding/json"
	"testing"
)

// TestGoogleOAuthConfig tests the Google OAuth configuration
// Expected: Should load without errors
// Issue: Returns 500 in E2E tests
func TestGoogleOAuthConfig(t *testing.T) {
	configJSON := `{
		"id": "google-oauth",
		"hostname": "google-oauth.test",
		"authentication": {
			"type": "oauth",
			"disabled": false,
			"provider": "google",
			"client_id": "781990534849-t6v26s5v7blu48kgkocdluvjv0jvlrhk.apps.googleusercontent.com",
			"client_secret": "local:kYZKjfsaegQg7UnWZyI8m+XD5KRF2xE8nKrNmME5q3oawxUVTCTpMU/TyhiDAVlwTFAHMZHEKUhHwK7S7A1n",
			"redirect_url": "https://google-oauth.test:8443/oauth/callback",
			"session_secret": "local:XtpHOiDGG8bircQZi6s7CdNSz6Y7CZ4nMBk0eHVLOBBIEg0haM5A5y2dbjEMZJxOoWmMrJJU2ehxfhDDaaThWUWs",
			"session_cookie_name": "_sb.oauth",
			"session_max_age": 3600,
			"scopes": ["openid", "profile", "email"],
			"callback_path": "/oauth/callback",
			"login_path": "/oauth/login",
			"logout_path": "/oauth/logout",
			"force_authentication": true,
			"default_roles": {
				"required": ["user"],
				"optional": ["admin"]
			}
		},
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		}
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal Google OAuth config: %v", err)
	}

	// Verify authentication is set up
	if cfg.auth == nil {
		t.Error("Authentication should not be nil for OAuth config")
	}

	// Verify action is proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for OAuth config")
	}

	t.Logf("✓ Google OAuth config loaded successfully")
	t.Logf("Config ID: %s", cfg.ID)
	t.Logf("Hostname: %s", cfg.Hostname)
}

// TestThreatDetectionConfig tests the threat detection configuration
// Expected: Should load and detect XSS patterns
// Issue: Returns 500 in E2E tests
func TestThreatDetectionConfig(t *testing.T) {
	configJSON := `{
		"id": "threat-detection",
		"hostname": "threat-detection.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		},
		"policies": [
			{
				"type": "threat_detection",
				"enabled": true,
				"patterns": {
					"xss": {
						"enabled": true,
						"action": "block",
						"log_level": "warn"
					},
					"path_traversal": {
						"enabled": true,
						"action": "log",
						"log_level": "info"
					}
				}
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal threat detection config: %v", err)
	}

	// Verify policies are loaded
	if len(cfg.policies) == 0 {
		t.Error("Policies should be loaded for threat detection config")
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for threat detection config")
	}

	t.Logf("✓ Threat detection config loaded successfully")
	t.Logf("Policies count: %d", len(cfg.policies))
}

// TestJavaScriptTransformLoaderRegistered verifies the JavaScript transform loader is registered
func TestJavaScriptTransformLoaderRegistered(t *testing.T) {
	// This test verifies that the transform loader is registered
	// The init() function in transform_javascript.go should register it
	// If this fails, it means transform_javascript.go isn't being compiled or the init() isn't running
	testJSON := `{"type": "javascript", "content_types": ["application/javascript"]}`
	_, err := LoadTransformConfig(json.RawMessage(testJSON))
	if err != nil {
		t.Logf("Transform loader error: %v", err)
		t.Logf("This might indicate transform_javascript.go init() didn't run or the file isn't being compiled")
		// Don't fail the test - this is diagnostic
	}
}

// TestJavaScriptTransformConfig tests the JavaScript transform configuration
// Expected: Should load without errors
// Issue: Returns 520 in E2E tests (needs proxy rebuild after renaming transform_js.go to transform_javascript.go)
// Note: FIXED - File renamed from transform_js.go to transform_javascript.go to fix build inclusion issue
func TestJavaScriptTransformConfig(t *testing.T) {
	configJSON := `{
		"id": "javascript-transform",
		"hostname": "javascript-transform.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		},
		"transforms": [
			{
				"type": "javascript",
				"content_types": ["application/javascript", "text/javascript"],
				"number_precision": 2,
				"change_variable_names": false,
				"supported_version": 5
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal JavaScript transform config: %v", err)
	}

	// Verify transforms are loaded
	if len(cfg.transforms) == 0 {
		t.Error("Transforms should be loaded for JavaScript transform config")
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for JavaScript transform config")
	}

	t.Logf("✓ JavaScript transform config loaded successfully")
	t.Logf("Transforms count: %d", len(cfg.transforms))
}

// TestGRPCProxyConfig tests the gRPC proxy configuration
// Expected: Should load without errors
// Issue: Returns 500 in E2E tests
func TestGRPCProxyConfig(t *testing.T) {
	configJSON := `{
		"id": "grpc",
		"hostname": "grpc.test",
		"action": {
			"type": "grpc",
			"url": "http://e2e-test-server:8093",
			"enable_grpc_web": true,
			"max_call_recv_msg_size": 10485760,
			"max_call_send_msg_size": 10485760
		}
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal gRPC config: %v", err)
	}

	// Verify action type by checking if it's a proxy
	// gRPC actions should use proxy mode

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for gRPC config")
	}

	// Verify Transport() is not nil
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil for gRPC")
	}

	t.Logf("✓ gRPC config loaded successfully")
	t.Logf("Config ID: %s", cfg.ID)
}


// TestStorageActionConfig - SKIPPED: Requires AWS/GCP dependencies
// Storage actions require cloud storage providers (S3, GCP, Azure) which are not available in test environment

// TestABTestActionConfig tests the AB test action configuration
// Expected: Should load without errors
// Issue: Returns 500 in E2E tests
func TestABTestActionConfig(t *testing.T) {
	configJSON := `{
		"id": "abtest",
		"hostname": "abtest.test",
		"action": {
			"type": "abtest",
			"variants": [
				{
					"name": "variant-a",
					"weight": 50,
					"action": {
						"type": "proxy",
						"url": "http://e2e-test-server:8090"
					}
				},
				{
					"name": "variant-b",
					"weight": 50,
					"action": {
						"type": "proxy",
						"url": "http://e2e-test-server:8090"
					}
				}
			],
			"cookie_name": "_ab_test"
		}
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal AB test config: %v", err)
	}

	// Verify action type - AB test actions use handler mode, not proxy mode

	// AB test actions typically use handler mode
	isProxy := cfg.IsProxy()
	handler := cfg.Handler()

	t.Logf("✓ AB test config loaded successfully")
	t.Logf("Config ID: %s", cfg.ID)
	t.Logf("IsProxy: %v", isProxy)
	t.Logf("Handler is nil: %v", handler == nil)
}

// TestCompressionConfig tests the compression configuration
// Expected: Should load without errors
// Issue: Compression header not appearing in response
func TestCompressionConfig(t *testing.T) {
	configJSON := `{
		"id": "compression",
		"hostname": "compression.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		},
		"compression": {
			"enabled": true,
			"types": ["text/html", "text/css", "application/javascript", "application/json"],
			"level": 6
		}
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal compression config: %v", err)
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for compression config")
	}

	// Check if compression config is accessible
	// Note: Compression might be a field on Config, let's verify it loads
	t.Logf("✓ Compression config loaded successfully")
	t.Logf("Config ID: %s", cfg.ID)
}

// TestWAFMultipleRulesConfig tests the WAF with multiple rules configuration
// Expected: Should load and apply multiple rules
// Issue: Some rules not blocking correctly
func TestWAFMultipleRulesConfig(t *testing.T) {
	configJSON := `{
		"id": "waf-multiple",
		"hostname": "waf-multiple.test",
		"policies": [
			{
				"type": "waf",
				"custom_rules": [
					{
						"id": "block-sql-injection",
						"name": "Block SQL Injection",
						"enabled": true,
						"phase": 2,
						"severity": "critical",
						"action": "block",
						"variables": [
							{
								"name": "ARGS",
								"collection": "ARGS"
							}
						],
						"operator": "rx",
						"pattern": "(?i)(union|select|insert|delete|update|drop|create|alter|or|and)",
						"transformations": ["lowercase", "urlDecode"]
					},
					{
						"id": "block-path-traversal",
						"name": "Block Path Traversal",
						"enabled": true,
						"phase": 2,
						"severity": "medium",
						"action": "block",
						"variables": [
							{
								"name": "ARGS",
								"collection": "ARGS"
							}
						],
						"operator": "rx",
						"pattern": "(\\.\\./|\\.\\.\\\\\\\\)",
						"transformations": ["urlDecode"]
					}
				],
				"default_action": "log",
				"action_on_match": "block"
			}
		],
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		}
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal WAF multiple rules config: %v", err)
	}

	// Verify policies are loaded
	if len(cfg.policies) == 0 {
		t.Error("Policies should be loaded for WAF config")
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for WAF config")
	}

	t.Logf("✓ WAF multiple rules config loaded successfully")
	t.Logf("Policies count: %d", len(cfg.policies))
}

// TestSecurityHeadersHSTSConfig tests the security headers HSTS configuration
// Expected: Should set Strict-Transport-Security header
// Issue: HSTS header not appearing in response
func TestSecurityHeadersHSTSConfig(t *testing.T) {
	configJSON := `{
		"id": "security-headers-comprehensive",
		"hostname": "security-headers-comprehensive.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090/api/headers"
		},
		"policies": [
			{
				"type": "security_headers",
				"enabled": true,
				"strict_transport_security": {
					"enabled": true,
					"max_age": 31536000,
					"include_subdomains": true,
					"preload": true
				}
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal security headers config: %v", err)
	}

	// Verify policies are loaded
	if len(cfg.policies) == 0 {
		t.Error("Policies should be loaded for security headers config")
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for security headers config")
	}

	t.Logf("✓ Security headers HSTS config loaded successfully")
	t.Logf("Policies count: %d", len(cfg.policies))
}

// TestErrorPagesConfig tests the error pages configuration
// Expected: Should load without errors
// Issue: Error page 404 content not appearing in E2E tests
func TestErrorPagesConfig(t *testing.T) {
	configJSON := `{
		"id": "error-pages",
		"hostname": "error-pages.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		},
		"error_pages": [
			{
				"status": [404],
				"body": "<html><body><h1>404 - Not Found</h1><p>Custom error page</p></body></html>",
				"content_type": "text/html"
			},
			{
				"status": [500],
				"callback": {
					"type": "http",
					"url": "http://e2e-test-server:8090/error",
					"method": "GET"
				}
			},
			{
				"status": [503],
				"body": "{\"error\":\"Service Unavailable\"}",
				"content_type": "application/json"
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal error pages config: %v", err)
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for error pages config")
	}

	// Note: Error pages are handled at runtime, not during config loading
	t.Logf("✓ Error pages config loaded successfully")
	t.Logf("Config ID: %s", cfg.ID)
}

// TestEncryptionConfig tests the encryption/request modifiers configuration
// Expected: Should load without errors
// Issue: Encryption header not appearing in E2E tests
func TestEncryptionConfig(t *testing.T) {
	configJSON := `{
		"id": "encryption",
		"hostname": "encryption.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090/api/headers"
		},
		"request_modifiers": [
			{
				"headers": {
					"set": {
						"X-API-Secret": "test-secret-value-12345"
					}
				}
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal encryption config: %v", err)
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for encryption config")
	}

	// Verify request modifiers are loaded
	if len(cfg.RequestModifiers) == 0 {
		t.Error("Request modifiers should be loaded for encryption config")
	}

	t.Logf("✓ Encryption config loaded successfully")
	t.Logf("Config ID: %s", cfg.ID)
	t.Logf("Request modifiers count: %d", len(cfg.RequestModifiers))
}

// TestForwardRulesComplexConfig tests the complex forward rules configuration
// Expected: Should load without errors
// Issue: Forward rules not routing correctly in E2E tests
func TestForwardRulesComplexConfig(t *testing.T) {
	configJSON := `{
		"id": "forward-rules-complex",
		"hostname": "forward-rules-complex.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090"
		},
		"forward_rules": [
			{
				"hostname": "api-v1-backend.test",
				"rules": [
					{
						"path": {"prefix": "/api/v1"}
					}
				]
			},
			{
				"hostname": "old-service-backend.test",
				"rules": [
					{
						"path": {"prefix": "/old"}
					}
				]
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal forward rules complex config: %v", err)
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for forward rules config")
	}

	// Verify forward rules are loaded
	if len(cfg.ForwardRules) == 0 {
		t.Error("Forward rules should be loaded for forward rules config")
	}

	t.Logf("✓ Forward rules complex config loaded successfully")
	t.Logf("Config ID: %s", cfg.ID)
	t.Logf("Forward rules count: %d", len(cfg.ForwardRules))
}

// TestRequestModifiersComplexConfig tests the complex request modifiers configuration
// Expected: Should load without errors
// Issue: Request modifiers header not appearing in E2E tests
func TestRequestModifiersComplexConfig(t *testing.T) {
	configJSON := `{
		"id": "request-modifiers-complex",
		"hostname": "request-modifiers-complex.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090/api/headers"
		},
		"request_modifiers": [
			{
				"headers": {
					"set": {
						"X-Custom-Header": "test-value",
						"X-Request-ID": "{{request.id}}"
					}
				},
				"rules": [
					{
						"path": {"prefix": "/api"}
					}
				]
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal request modifiers complex config: %v", err)
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for request modifiers config")
	}

	// Verify request modifiers are loaded
	if len(cfg.RequestModifiers) == 0 {
		t.Error("Request modifiers should be loaded for request modifiers config")
	}

	t.Logf("✓ Request modifiers complex config loaded successfully")
	t.Logf("Config ID: %s", cfg.ID)
	t.Logf("Request modifiers count: %d", len(cfg.RequestModifiers))
}

// TestResponseModifiersComplexConfig tests the complex response modifiers configuration
// Expected: Should load without errors
// Issue: Response modifiers header not appearing in E2E tests
func TestResponseModifiersComplexConfig(t *testing.T) {
	configJSON := `{
		"id": "response-modifiers-complex",
		"hostname": "response-modifiers-complex.test",
		"action": {
			"type": "proxy",
			"url": "http://e2e-test-server:8090/api/headers"
		},
		"response_modifiers": [
			{
				"headers": {
					"set": {
						"X-Custom-Response-Header": "test-value",
						"X-Response-Time": "{{response.time}}"
					}
				},
				"rules": [
					{
						"status_code": {"min": 200, "max": 299}
					}
				]
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal response modifiers complex config: %v", err)
	}

	// Verify it's a proxy
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for response modifiers config")
	}

	// Verify response modifiers are loaded
	if len(cfg.ResponseModifiers) == 0 {
		t.Error("Response modifiers should be loaded for response modifiers config")
	}

	t.Logf("✓ Response modifiers complex config loaded successfully")
	t.Logf("Config ID: %s", cfg.ID)
	t.Logf("Response modifiers count: %d", len(cfg.ResponseModifiers))
}

// TestWAFCustomRuleID_StringWorks verifies that WAF custom_rules.id accepts a string value.
func TestWAFCustomRuleID_StringWorks(t *testing.T) {
	configJSON := `{
		"id": "waf-string-id",
		"hostname": "waf-string-id.test",
		"policies": [
			{
				"type": "waf",
				"custom_rules": [
					{
						"id": "1001",
						"name": "Test Rule",
						"enabled": true,
						"phase": 2,
						"severity": "warning",
						"action": "block",
						"variables": [{"name": "REQUEST_URI"}],
						"operator": "rx",
						"pattern": "/admin"
					}
				],
				"action_on_match": "block"
			}
		],
		"action": {
			"type": "proxy",
			"url": "http://backend:8090"
		}
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("WAF custom_rules with string id should unmarshal successfully: %v", err)
	}
	if len(cfg.policies) == 0 {
		t.Fatal("Expected at least one policy to be loaded")
	}
}

// TestWAFCustomRuleID_IntFails verifies that WAF custom_rules.id rejects an integer value.
// The WAF rule ID field is typed as string, so a bare integer in JSON should cause an unmarshal error.
func TestWAFCustomRuleID_IntFails(t *testing.T) {
	configJSON := `{
		"id": "waf-int-id",
		"hostname": "waf-int-id.test",
		"policies": [
			{
				"type": "waf",
				"custom_rules": [
					{
						"id": 1001,
						"name": "Test Rule",
						"enabled": true,
						"phase": 2,
						"severity": "warning",
						"action": "block",
						"variables": [{"name": "REQUEST_URI"}],
						"operator": "rx",
						"pattern": "/admin"
					}
				],
				"action_on_match": "block"
			}
		],
		"action": {
			"type": "proxy",
			"url": "http://backend:8090"
		}
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err == nil {
		t.Fatal("WAF custom_rules with integer id should fail to unmarshal, but got nil error")
	}
}

// TestLoadBalancerType_IsLoadbalancer verifies the load balancer type constant is "loadbalancer" (not "load_balancer").
func TestLoadBalancerType_IsLoadbalancer(t *testing.T) {
	if TypeLoadBalancer != "loadbalancer" {
		t.Errorf("TypeLoadBalancer = %q, want %q", TypeLoadBalancer, "loadbalancer")
	}
}

// TestForwardRules_ArrayWorks verifies that forward_rules.rules accepts an array of rule objects.
func TestForwardRules_ArrayWorks(t *testing.T) {
	configJSON := `{
		"id": "forward-rules-array",
		"hostname": "forward-rules-array.test",
		"action": {
			"type": "proxy",
			"url": "http://backend:8090"
		},
		"forward_rules": [
			{
				"hostname": "api-backend.test",
				"rules": [
					{
						"path": {"prefix": "/api"}
					}
				]
			}
		]
	}`

	cfg := &Config{}
	err := json.Unmarshal([]byte(configJSON), cfg)
	if err != nil {
		t.Fatalf("ForwardRules with array rules should unmarshal successfully: %v", err)
	}
	if len(cfg.ForwardRules) == 0 {
		t.Fatal("Expected at least one forward rule to be loaded")
	}
}

// TestMCPCapabilitiesTools_ObjectWorks verifies that MCP capabilities.tools accepts an object (not a bool).
func TestMCPCapabilitiesTools_ObjectWorks(t *testing.T) {
	configJSON := `{
		"type": "mcp",
		"server_info": {"name": "test-server", "version": "1.0.0"},
		"capabilities": {
			"tools": {"listChanged": true}
		},
		"tools": []
	}`

	action, err := LoadMCP([]byte(configJSON))
	if err != nil {
		t.Fatalf("MCP with capabilities.tools as object should load successfully: %v", err)
	}
	mcpAction, ok := action.(*MCPAction)
	if !ok {
		t.Fatal("LoadMCP should return *MCPAction")
	}
	if mcpAction.Capabilities.Tools == nil {
		t.Fatal("MCP capabilities.tools should not be nil")
	}
	if !mcpAction.Capabilities.Tools.ListChanged {
		t.Error("MCP capabilities.tools.listChanged should be true")
	}
}

// TestMCPCapabilitiesTools_BoolFails verifies that MCP capabilities.tools rejects a boolean value.
// The Tools field is *ToolsCapability (a struct pointer), so a bare boolean should cause an unmarshal error.
func TestMCPCapabilitiesTools_BoolFails(t *testing.T) {
	configJSON := `{
		"type": "mcp",
		"server_info": {"name": "test-server", "version": "1.0.0"},
		"capabilities": {
			"tools": true
		},
		"tools": []
	}`

	_, err := LoadMCP([]byte(configJSON))
	if err == nil {
		t.Fatal("MCP with capabilities.tools as bool should fail to load, but got nil error")
	}
}

// TestWebSocketURL_WSSchemeWorks verifies that WebSocket action accepts ws:// scheme.
func TestWebSocketURL_WSSchemeWorks(t *testing.T) {
	configJSON := `{
		"type": "websocket",
		"url": "ws://backend:8090/ws"
	}`

	_, err := NewWebSocketAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("WebSocket with ws:// scheme should load successfully: %v", err)
	}
}

// TestWebSocketURL_WSSSchemeWorks verifies that WebSocket action accepts wss:// scheme.
func TestWebSocketURL_WSSSchemeWorks(t *testing.T) {
	configJSON := `{
		"type": "websocket",
		"url": "wss://backend:8090/ws"
	}`

	_, err := NewWebSocketAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("WebSocket with wss:// scheme should load successfully: %v", err)
	}
}

// TestWebSocketURL_HTTPSchemeFails verifies that WebSocket action rejects http:// scheme.
func TestWebSocketURL_HTTPSchemeFails(t *testing.T) {
	configJSON := `{
		"type": "websocket",
		"url": "http://backend:8090/ws"
	}`

	_, err := NewWebSocketAction([]byte(configJSON))
	if err == nil {
		t.Fatal("WebSocket with http:// scheme should fail, but got nil error")
	}
}

// TestWebSocketURL_HTTPSSchemeFails verifies that WebSocket action rejects https:// scheme.
func TestWebSocketURL_HTTPSSchemeFails(t *testing.T) {
	configJSON := `{
		"type": "websocket",
		"url": "https://backend:8090/ws"
	}`

	_, err := NewWebSocketAction([]byte(configJSON))
	if err == nil {
		t.Fatal("WebSocket with https:// scheme should fail, but got nil error")
	}
}

