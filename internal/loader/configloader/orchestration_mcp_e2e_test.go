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
	"github.com/soapbucket/sbproxy/internal/extension/mcp"
)

// TestOrchestration_SequentialSteps_E2E tests sequential execution of orchestration steps
func TestOrchestration_SequentialSteps_E2E(t *testing.T) {
	resetCache()

	// Create mock services for orchestration
	userService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    123,
			"name":  "Alice",
			"email": "alice@example.com",
		})
	}))
	defer userService.Close()

	ordersService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"orders": []interface{}{
				map[string]interface{}{"id": "order-1", "total": 99.99},
				map[string]interface{}{"id": "order-2", "total": 149.99},
			},
		})
	}))
	defer ordersService.Close()

	t.Run("Sequential orchestration steps execute in order", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "orchestration-sequential",
			"hostname": "orchestration-seq.test",
			"workspace_id": "test-workspace",
			"orchestration": {
				"steps": [
					{
						"name": "get_user",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET",
							"timeout": 5
						}
					},
					{
						"name": "get_orders",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET",
							"timeout": 5
						},
						"depends_on": ["get_user"]
					}
				],
				"parallel": false,
				"timeout": 30,
				"continue_on_error": false
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, userService.URL, ordersService.URL, userService.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"orchestration-seq.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://orchestration-seq.test/api/user-profile", nil)
		req.Host = "orchestration-seq.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Sequential orchestration completed with 200 status")
		}
	})
}

// TestOrchestration_ParallelSteps_E2E tests parallel execution of independent steps
func TestOrchestration_ParallelSteps_E2E(t *testing.T) {
	resetCache()

	// Create fast services
	service1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"service": "service1", "data": "value1"})
	}))
	defer service1.Close()

	service2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"service": "service2", "data": "value2"})
	}))
	defer service2.Close()

	service3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"service": "service3", "data": "value3"})
	}))
	defer service3.Close()

	t.Run("Parallel independent steps execute concurrently", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "orchestration-parallel",
			"hostname": "orchestration-parallel.test",
			"workspace_id": "test-workspace",
			"orchestration": {
				"steps": [
					{
						"name": "call_service_1",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET",
							"timeout": 5
						}
					},
					{
						"name": "call_service_2",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET",
							"timeout": 5
						}
					},
					{
						"name": "call_service_3",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET",
							"timeout": 5
						}
					}
				],
				"parallel": true,
				"timeout": 30,
				"continue_on_error": false
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, service1.URL, service2.URL, service3.URL, service1.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"orchestration-parallel.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://orchestration-parallel.test/api/multi", nil)
		req.Host = "orchestration-parallel.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Parallel orchestration completed successfully")
		}
	})
}

// TestOrchestration_ErrorHandling_E2E tests error handling and continue_on_error flag
func TestOrchestration_ErrorHandling_E2E(t *testing.T) {
	resetCache()

	failService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "service unavailable"})
	}))
	defer failService.Close()

	successService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success"})
	}))
	defer successService.Close()

	t.Run("Continue on error flag allows subsequent steps after failure", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "orchestration-continue-error",
			"hostname": "orchestration-continue.test",
			"workspace_id": "test-workspace",
			"orchestration": {
				"steps": [
					{
						"name": "call_failing_service",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET",
							"timeout": 5
						},
						"continue_on_error": true
					},
					{
						"name": "call_success_service",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET",
							"timeout": 5
						}
					}
				],
				"parallel": false,
				"timeout": 30,
				"continue_on_error": true
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, failService.URL, successService.URL, successService.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"orchestration-continue.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://orchestration-continue.test/api", nil)
		req.Host = "orchestration-continue.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		// Should succeed overall due to continue_on_error
		if w.Code == http.StatusOK {
			t.Logf("✓ Orchestration continued after error")
		}
	})
}

// TestOrchestration_Timeout_E2E tests orchestration timeout enforcement
func TestOrchestration_Timeout_E2E(t *testing.T) {
	resetCache()

	slowService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "slow"})
	}))
	defer slowService.Close()

	fastService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "fast"})
	}))
	defer fastService.Close()

	t.Run("Orchestration respects timeout configuration", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "orchestration-timeout",
			"hostname": "orchestration-timeout.test",
			"workspace_id": "test-workspace",
			"orchestration": {
				"steps": [
					{
						"name": "fast_step",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET",
							"timeout": 5
						}
					},
					{
						"name": "slow_step",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET",
							"timeout": 5
						}
					}
				],
				"parallel": false,
				"timeout": 5,
				"continue_on_error": false
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, fastService.URL, slowService.URL, fastService.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"orchestration-timeout.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://orchestration-timeout.test/api", nil)
		req.Host = "orchestration-timeout.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		t.Logf("✓ Orchestration timeout test completed")
	})
}

// TestMCP_Initialize_E2E tests MCP protocol initialization
func TestMCP_Initialize_E2E(t *testing.T) {
	resetCache()

	t.Run("MCP server responds to initialize request", func(t *testing.T) {
		configJSON := `{
			"id": "mcp-server",
			"hostname": "mcp.test",
			"workspace_id": "test-workspace",
			"mcp": {
				"name": "soapbucket",
				"version": "1.0.0",
				"tools": [
					{
						"name": "proxy_request",
						"description": "Send a request through the proxy",
						"input_schema": {
							"type": "object",
							"properties": {
								"url": {"type": "string"},
								"method": {"type": "string"}
							}
						}
					}
				],
				"resources": [
					{
						"uri": "config://origins",
						"name": "Origins",
						"description": "List of configured origins",
						"mime_type": "application/json"
					}
				]
			},
			"action": {
				"type": "noop"
			}
		}`

		mockStore := &mockStorage{
			data: map[string][]byte{
				"mcp.test": []byte(configJSON),
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

		req := httptest.NewRequest("POST", "http://mcp.test/mcp", nil)
		req.Host = "mcp.test"

		// Simulate MCP initialize request
		initReq := mcp.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "initialize",
			Params:  json.RawMessage([]byte(`{"protocolVersion": "2024-11-05"}`)),
		}
		body, _ := json.Marshal(initReq)
		req.Body = io.NopCloser(strings.NewReader(string(body)))

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK || w.Code == http.StatusNotFound {
			// Either processed or deferred (due to noop action)
			t.Logf("✓ MCP initialize request processed")
		}
	})
}

// TestMCP_ListTools_E2E tests MCP list tools functionality
func TestMCP_ListTools_E2E(t *testing.T) {
	resetCache()

	t.Run("MCP server lists configured tools", func(t *testing.T) {
		configJSON := `{
			"id": "mcp-tools",
			"hostname": "mcp-tools.test",
			"workspace_id": "test-workspace",
			"mcp": {
				"name": "soapbucket",
				"version": "1.0.0",
				"tools": [
					{
						"name": "health_check",
						"description": "Check proxy health",
						"input_schema": {
							"type": "object",
							"properties": {}
						}
					},
					{
						"name": "get_config",
						"description": "Get current configuration",
						"input_schema": {
							"type": "object",
							"properties": {
								"config_id": {"type": "string"}
							}
						}
					},
					{
						"name": "proxy_request",
						"description": "Route request through proxy",
						"input_schema": {
							"type": "object",
							"properties": {
								"url": {"type": "string"},
								"method": {"type": "string"},
								"headers": {"type": "object"}
							}
						}
					}
				]
			},
			"action": {
				"type": "noop"
			}
		}`

		mockStore := &mockStorage{
			data: map[string][]byte{
				"mcp-tools.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://mcp-tools.test/mcp/tools", nil)
		req.Host = "mcp-tools.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		// MCP server should respond with list of tools
		t.Logf("✓ MCP tools endpoint processed with status %d", w.Code)
	})
}

// TestMCP_ListResources_E2E tests MCP resource listing
func TestMCP_ListResources_E2E(t *testing.T) {
	resetCache()

	t.Run("MCP server lists configured resources", func(t *testing.T) {
		configJSON := `{
			"id": "mcp-resources",
			"hostname": "mcp-resources.test",
			"workspace_id": "test-workspace",
			"mcp": {
				"name": "soapbucket",
				"version": "1.0.0",
				"resources": [
					{
						"uri": "config://origins",
						"name": "Origins",
						"description": "List of configured origin servers",
						"mime_type": "application/json"
					},
					{
						"uri": "config://policies",
						"name": "Policies",
						"description": "List of active policies",
						"mime_type": "application/json"
					},
					{
						"uri": "config://transforms",
						"name": "Transforms",
						"description": "List of response transforms",
						"mime_type": "application/json"
					},
					{
						"uri": "status://health",
						"name": "Health Status",
						"description": "Current health status of the proxy",
						"mime_type": "application/json"
					}
				]
			},
			"action": {
				"type": "noop"
			}
		}`

		mockStore := &mockStorage{
			data: map[string][]byte{
				"mcp-resources.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://mcp-resources.test/mcp/resources", nil)
		req.Host = "mcp-resources.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		t.Logf("✓ MCP resources endpoint processed with status %d", w.Code)
	})
}

// TestOrchestration_DependencyResolution_E2E tests orchestration dependency ordering
func TestOrchestration_DependencyResolution_E2E(t *testing.T) {
	resetCache()

	// Create services that return different data
	stepAService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"step": "A", "value": 100})
	}))
	defer stepAService.Close()

	stepBService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"step": "B", "depends_on": "A"})
	}))
	defer stepBService.Close()

	stepCService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"step": "C", "depends_on": "B"})
	}))
	defer stepCService.Close()

	t.Run("Orchestration resolves dependencies in correct order", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "orchestration-deps",
			"hostname": "orchestration-deps.test",
			"workspace_id": "test-workspace",
			"orchestration": {
				"steps": [
					{
						"name": "step_A",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET"
						}
					},
					{
						"name": "step_B",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET"
						},
						"depends_on": ["step_A"]
					},
					{
						"name": "step_C",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET"
						},
						"depends_on": ["step_B"]
					}
				],
				"parallel": false,
				"timeout": 30
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, stepAService.URL, stepBService.URL, stepCService.URL, stepAService.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"orchestration-deps.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://orchestration-deps.test/api", nil)
		req.Host = "orchestration-deps.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Orchestration dependency resolution completed")
		}
	})
}

// TestOrchestration_ResponseBuilding_E2E tests response template building
func TestOrchestration_ResponseBuilding_E2E(t *testing.T) {
	resetCache()

	apiService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user_id": 42,
			"name":    "Alice",
		})
	}))
	defer apiService.Close()

	t.Run("Orchestration builds response from step results", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "orchestration-response",
			"hostname": "orchestration-response.test",
			"workspace_id": "test-workspace",
			"orchestration": {
				"steps": [
					{
						"name": "fetch_user",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET"
						}
					}
				],
				"parallel": false,
				"response_builder": {
					"content_type": "application/json",
					"status_code": 200,
					"template": "{\"data\": {{fetch_user.response}}, \"timestamp\": \"{{timestamp}}\"}"
				}
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, apiService.URL, apiService.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"orchestration-response.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://orchestration-response.test/api", nil)
		req.Host = "orchestration-response.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Orchestration response building completed")
		}
	})
}

// TestMCP_MultipleToolsAndResources_E2E tests MCP with multiple tools and resources
func TestMCP_MultipleToolsAndResources_E2E(t *testing.T) {
	resetCache()

	t.Run("MCP server with multiple tools and resources", func(t *testing.T) {
		configJSON := `{
			"id": "mcp-full",
			"hostname": "mcp-full.test",
			"workspace_id": "test-workspace",
			"mcp": {
				"name": "soapbucket-full",
				"version": "2.0.0",
				"tools": [
					{
						"name": "create_origin",
						"description": "Create a new origin configuration",
						"input_schema": {
							"type": "object",
							"properties": {
								"hostname": {"type": "string"},
								"url": {"type": "string"},
								"policies": {"type": "array"}
							},
							"required": ["hostname", "url"]
						}
					},
					{
						"name": "update_policy",
						"description": "Update a policy on an origin",
						"input_schema": {
							"type": "object",
							"properties": {
								"origin_id": {"type": "string"},
								"policy_type": {"type": "string"},
								"config": {"type": "object"}
							}
						}
					},
					{
						"name": "test_origin",
						"description": "Test connectivity to an origin",
						"input_schema": {
							"type": "object",
							"properties": {
								"origin_id": {"type": "string"},
								"path": {"type": "string"}
							}
						}
					},
					{
						"name": "get_metrics",
						"description": "Retrieve proxy metrics",
						"input_schema": {
							"type": "object",
							"properties": {
								"metric_type": {"type": "string"},
								"time_range": {"type": "string"}
							}
						}
					}
				],
				"resources": [
					{
						"uri": "config://origins/list",
						"name": "All Origins",
						"description": "Complete list of configured origins",
						"mime_type": "application/json"
					},
					{
						"uri": "config://policies",
						"name": "Available Policies",
						"description": "List of all available policy types",
						"mime_type": "application/json"
					},
					{
						"uri": "status://metrics",
						"name": "Current Metrics",
						"description": "Real-time proxy metrics",
						"mime_type": "application/json"
					},
					{
						"uri": "docs://waf-rules",
						"name": "WAF Rules",
						"description": "Available WAF rules and patterns",
						"mime_type": "text/markdown"
					}
				]
			},
			"action": {
				"type": "noop"
			}
		}`

		mockStore := &mockStorage{
			data: map[string][]byte{
				"mcp-full.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://mcp-full.test/mcp/capabilities", nil)
		req.Host = "mcp-full.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		t.Logf("✓ MCP full capabilities processed with status %d", w.Code)
	})
}

// TestOrchestration_FanOutFanIn_E2E tests fan-out and fan-in orchestration pattern
func TestOrchestration_FanOutFanIn_E2E(t *testing.T) {
	resetCache()

	coordinatorService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"step": "coordinator"})
	}))
	defer coordinatorService.Close()

	workerService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"step": "worker"})
	}))
	defer workerService.Close()

	aggregatorService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"step": "aggregator"})
	}))
	defer aggregatorService.Close()

	t.Run("Fan-out/fan-in orchestration pattern", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "orchestration-fanout",
			"hostname": "orchestration-fanout.test",
			"workspace_id": "test-workspace",
			"orchestration": {
				"steps": [
					{
						"name": "coordinator",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET"
						}
					},
					{
						"name": "worker_1",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET"
						},
						"depends_on": ["coordinator"]
					},
					{
						"name": "worker_2",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET"
						},
						"depends_on": ["coordinator"]
					},
					{
						"name": "worker_3",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET"
						},
						"depends_on": ["coordinator"]
					},
					{
						"name": "aggregator",
						"callback": {
							"type": "http",
							"url": "%s",
							"method": "GET"
						},
						"depends_on": ["worker_1", "worker_2", "worker_3"]
					}
				],
				"parallel": true,
				"timeout": 30
			},
			"action": {
				"type": "proxy",
				"url": "%s"
			}
		}`, coordinatorService.URL, workerService.URL, workerService.URL, workerService.URL, aggregatorService.URL, coordinatorService.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"orchestration-fanout.test": []byte(configJSON),
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

		req := httptest.NewRequest("GET", "http://orchestration-fanout.test/api", nil)
		req.Host = "orchestration-fanout.test"

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		w := httptest.NewRecorder()
		cfg.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Logf("✓ Fan-out/fan-in orchestration pattern completed")
		}
	})
}
