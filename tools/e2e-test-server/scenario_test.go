package main

import (
	"encoding/json"
	"testing"
)

func TestScenarioIndexing(t *testing.T) {
	// Test config with scenarios including path-based ones
	configJSON := `{
		"name": "Test Config",
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
						"message": "Old service test endpoint"
					}
				}
			},
			{
				"id": "test-scenario",
				"name": "Test Scenario",
				"path": "/test/test-scenario",
				"method": "GET",
				"response": {
					"status": 200
				}
			}
		]
	}`

	var config TestConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Create server and index scenarios
	server := &Server{
		scenarios:       make(map[string]TestScenario),
		scenariosByPath: make(map[string]TestScenario),
	}

	// Index scenarios by ID and path
	for _, scenario := range config.Scenarios {
		server.scenarios[scenario.ID] = scenario
		if scenario.Path != "" {
			server.scenariosByPath[scenario.Path] = scenario
		}
	}

	// Test that scenarios are indexed correctly
	tests := []struct {
		path     string
		expected bool
		id       string
	}{
		{"/api/v1/test", true, "api-v1-test"},
		{"/old/test", true, "old-test"},
		{"/test/test-scenario", true, "test-scenario"},
		{"/nonexistent", false, ""},
		{"/api/v2/test", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			scenario, exists := server.scenariosByPath[tt.path]
			if exists != tt.expected {
				t.Errorf("Expected exists=%v for path %s, got %v", tt.expected, tt.path, exists)
			}
			if exists && scenario.ID != tt.id {
				t.Errorf("Expected scenario ID %s for path %s, got %s", tt.id, tt.path, scenario.ID)
			}
		})
	}

	// Verify counts
	if len(server.scenarios) != 3 {
		t.Errorf("Expected 3 scenarios by ID, got %d", len(server.scenarios))
	}
	if len(server.scenariosByPath) != 3 {
		t.Errorf("Expected 3 scenarios by path, got %d", len(server.scenariosByPath))
	}
}

func TestScenarioPathMatching(t *testing.T) {
	// Test that path-based scenarios work correctly
	configJSON := `{
		"name": "Test Config",
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
		scenarios:       make(map[string]TestScenario),
		scenariosByPath: make(map[string]TestScenario),
	}

	for _, scenario := range config.Scenarios {
		server.scenarios[scenario.ID] = scenario
		if scenario.Path != "" {
			server.scenariosByPath[scenario.Path] = scenario
		}
	}

	// Verify the scenario is indexed
	scenario, exists := server.scenariosByPath["/api/v1/test"]
	if !exists {
		t.Fatal("Scenario /api/v1/test not found in scenariosByPath")
	}

	if scenario.ID != "api-v1-test" {
		t.Errorf("Expected scenario ID api-v1-test, got %s", scenario.ID)
	}

	if scenario.Path != "/api/v1/test" {
		t.Errorf("Expected scenario path /api/v1/test, got %s", scenario.Path)
	}

	if scenario.Method != "GET" {
		t.Errorf("Expected scenario method GET, got %s", scenario.Method)
	}
}

