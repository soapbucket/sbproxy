package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleScenarioByPath_ApiV1Test(t *testing.T) {
	// Load the actual test config
	configJSON := `{
		"name": "E2E Test Server Configuration",
		"scenarios": [
			{
				"id": "api-v1-test",
				"name": "API v1 Test Endpoint",
				"path": "/api/v1/test",
				"method": "GET",
				"response": {
					"status": 200,
					"headers": {
						"Content-Type": "application/json"
					},
					"body": {
						"status": "success",
						"message": "API v1 test endpoint",
						"path": "/api/v1/test"
					}
				}
			},
			{
				"id": "old-test",
				"name": "Old Service Test Endpoint",
				"path": "/old/test",
				"method": "GET",
				"response": {
					"status": 200,
					"headers": {
						"Content-Type": "application/json"
					},
					"body": {
						"status": "success",
						"message": "Old service test endpoint",
						"path": "/old/test"
					}
				}
			}
		]
	}`

	var config TestConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Create server
	server := &Server{
		config:          &config,
		scenarios:       make(map[string]TestScenario),
		scenariosByPath: make(map[string]TestScenario),
	}

	// Index scenarios
	for _, scenario := range config.Scenarios {
		server.scenarios[scenario.ID] = scenario
		if scenario.Path != "" {
			server.scenariosByPath[scenario.Path] = scenario
		}
	}

	// Verify scenarios are indexed
	if len(server.scenariosByPath) != 2 {
		t.Errorf("Expected 2 scenarios by path, got %d", len(server.scenariosByPath))
	}

	// Test /api/v1/test
	t.Run("/api/v1/test", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		w := httptest.NewRecorder()

		server.handleScenarioByPath(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		// Verify response body contains expected content
		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v. Body: %s", err, w.Body.String())
		}

		if response["status"] != "success" {
			t.Errorf("Expected status 'success', got %v", response["status"])
		}

		if response["path"] != "/api/v1/test" {
			t.Errorf("Expected path '/api/v1/test', got %v", response["path"])
		}
	})

	// Test /old/test
	t.Run("/old/test", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/old/test", nil)
		w := httptest.NewRecorder()

		server.handleScenarioByPath(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		// Verify response body contains expected content
		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v. Body: %s", err, w.Body.String())
		}

		if response["status"] != "success" {
			t.Errorf("Expected status 'success', got %v", response["status"])
		}

		if response["path"] != "/old/test" {
			t.Errorf("Expected path '/old/test', got %v", response["path"])
		}
	})
}

func TestHandleScenarioByPath_WithMux(t *testing.T) {
	// Test with actual HTTP mux to simulate real server behavior
	configJSON := `{
		"name": "E2E Test Server Configuration",
		"scenarios": [
			{
				"id": "api-v1-test",
				"name": "API v1 Test Endpoint",
				"path": "/api/v1/test",
				"method": "GET",
				"response": {
					"status": 200,
					"headers": {
						"Content-Type": "application/json"
					},
					"body": {
						"status": "success",
						"message": "API v1 test endpoint"
					}
				}
			}
		]
	}`

	var config TestConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Create server
	server := &Server{
		config:          &config,
		scenarios:       make(map[string]TestScenario),
		scenariosByPath: make(map[string]TestScenario),
	}

	// Index scenarios
	for _, scenario := range config.Scenarios {
		server.scenarios[scenario.ID] = scenario
		if scenario.Path != "" {
			server.scenariosByPath[scenario.Path] = scenario
		}
	}

	// Create mux and register handlers
	mux := http.NewServeMux()
	server.registerHTTPHandlers(mux)

	// Test request through mux
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		t.Logf("Response headers: %v", w.Header())
	}

	// Verify response
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v. Body: %s", err, w.Body.String())
	}

	if response["status"] != "success" {
		t.Errorf("Expected status 'success', got %v", response["status"])
	}
}

func TestHandleRoot_DelegatesToScenarioByPath(t *testing.T) {
	// Test that handleRoot delegates non-root paths to handleScenarioByPath
	configJSON := `{
		"name": "E2E Test Server Configuration",
		"scenarios": [
			{
				"id": "api-v1-test",
				"name": "API v1 Test Endpoint",
				"path": "/api/v1/test",
				"method": "GET",
				"response": {
					"status": 200,
					"body": {
						"status": "success"
					}
				}
			}
		]
	}`

	var config TestConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	server := &Server{
		config:          &config,
		scenarios:       make(map[string]TestScenario),
		scenariosByPath: make(map[string]TestScenario),
	}

	// Index scenarios
	for _, scenario := range config.Scenarios {
		server.scenarios[scenario.ID] = scenario
		if scenario.Path != "" {
			server.scenariosByPath[scenario.Path] = scenario
		}
	}

	// Create mux
	mux := http.NewServeMux()
	server.registerHTTPHandlers(mux)

	// Test root path
	t.Run("root path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200 for root, got %d", w.Code)
		}
	})

	// Test scenario path through root handler
	t.Run("scenario path through root", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
}

