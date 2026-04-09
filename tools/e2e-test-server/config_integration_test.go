package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigLoadAndScenarioIndexing tests that the actual config file loads correctly
// and scenarios are properly indexed by both ID and path
func TestConfigLoadAndScenarioIndexing(t *testing.T) {
	// Find the config file (could be in current dir or parent)
	configPaths := []string{
		"test-config.json",
		"tools/e2e-test-server/test-config.json",
		"../tools/e2e-test-server/test-config.json",
	}

	var configPath string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}

	if configPath == "" {
		// Try to find it relative to test file location
		wd, _ := os.Getwd()
		absPath := filepath.Join(wd, "test-config.json")
		if _, err := os.Stat(absPath); err == nil {
			configPath = absPath
		}
	}

	if configPath == "" {
		t.Fatalf("Could not find test-config.json file. Tried: %v", configPaths)
	}

	t.Logf("Loading config from: %s", configPath)

	// Load config using the same function the server uses
	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config == nil {
		t.Fatalf("Config is nil")
	}

	t.Logf("Loaded config with %d scenarios", len(config.Scenarios))

	// Create server exactly as main() does
	server := &Server{
		config:          config,
		scenarios:       make(map[string]TestScenario),
		scenariosByPath: make(map[string]TestScenario),
	}

	// Index scenarios exactly as main() does
	for _, scenario := range config.Scenarios {
		server.scenarios[scenario.ID] = scenario
		if scenario.Path != "" {
			server.scenariosByPath[scenario.Path] = scenario
		}
	}

	// Verify critical scenarios exist
	requiredScenarios := []struct {
		id   string
		path string
	}{
		{"api-v1-test", "/api/v1/test"},
		{"old-test", "/old/test"},
	}

	for _, req := range requiredScenarios {
		t.Run(req.id, func(t *testing.T) {
			// Check by ID
			scenario, exists := server.scenarios[req.id]
			if !exists {
				t.Errorf("Scenario %s not found in scenarios map", req.id)
				t.Logf("Available scenario IDs: %v", getScenarioIDs(server.scenarios))
				return
			}

			if scenario.Path != req.path {
				t.Errorf("Scenario %s has path %s, expected %s", req.id, scenario.Path, req.path)
			}

			// Check by path
			scenarioByPath, exists := server.scenariosByPath[req.path]
			if !exists {
				t.Errorf("Scenario with path %s not found in scenariosByPath map", req.path)
				t.Logf("Available paths: %v", getScenarioPaths(server.scenariosByPath))
				return
			}

			if scenarioByPath.ID != req.id {
				t.Errorf("Scenario at path %s has ID %s, expected %s", req.path, scenarioByPath.ID, req.id)
			}
		})
	}

	// Log all scenarios for debugging
	t.Logf("Total scenarios indexed: %d by ID, %d by path", len(server.scenarios), len(server.scenariosByPath))
}

// TestServerStartupSimulation simulates the full server startup and tests HTTP handlers
func TestServerStartupSimulation(t *testing.T) {
	// Find config file
	configPaths := []string{
		"test-config.json",
		"tools/e2e-test-server/test-config.json",
		"../tools/e2e-test-server/test-config.json",
	}

	var configPath string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}

	if configPath == "" {
		wd, _ := os.Getwd()
		absPath := filepath.Join(wd, "test-config.json")
		if _, err := os.Stat(absPath); err == nil {
			configPath = absPath
		}
	}

	if configPath == "" {
		t.Fatalf("Could not find test-config.json file")
	}

	// Load config
	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create server exactly as main() does
	server := &Server{
		config:          config,
		scenarios:       make(map[string]TestScenario),
		scenariosByPath: make(map[string]TestScenario),
	}

	// Index scenarios exactly as main() does
	for _, scenario := range config.Scenarios {
		server.scenarios[scenario.ID] = scenario
		if scenario.Path != "" {
			server.scenariosByPath[scenario.Path] = scenario
		}
	}

	// Create mux and register handlers exactly as main() does
	mux := http.NewServeMux()
	server.registerHTTPHandlers(mux)

	// Test the critical paths
	testCases := []struct {
		name           string
		path           string
		method         string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "API v1 test endpoint",
			path:           "/api/v1/test",
			method:         "GET",
			expectedStatus: 200,
			expectedBody:   "API v1 test endpoint",
		},
		{
			name:           "Old service test endpoint",
			path:           "/old/test",
			method:         "GET",
			expectedStatus: 200,
			expectedBody:   "Old service test endpoint",
		},
		{
			name:           "Root path",
			path:           "/",
			method:         "GET",
			expectedStatus: 200,
			expectedBody:   "E2E Test Server",
		},
		{
			name:           "Health check",
			path:           "/health",
			method:         "GET",
			expectedStatus: 200,
			expectedBody:   "healthy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, w.Code, w.Body.String())
				t.Logf("Response headers: %v", w.Header())
			}

			if tc.expectedBody != "" && !strings.Contains(w.Body.String(), tc.expectedBody) {
				t.Errorf("Expected body to contain '%s', got: %s", tc.expectedBody, w.Body.String())
			}
		})
	}
}

// TestScenarioPathMatchingWithRealConfig tests that scenario paths match correctly
func TestScenarioPathMatchingWithRealConfig(t *testing.T) {
	configPaths := []string{
		"test-config.json",
		"tools/e2e-test-server/test-config.json",
		"../tools/e2e-test-server/test-config.json",
	}

	var configPath string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}

	if configPath == "" {
		wd, _ := os.Getwd()
		absPath := filepath.Join(wd, "test-config.json")
		if _, err := os.Stat(absPath); err == nil {
			configPath = absPath
		}
	}

	if configPath == "" {
		t.Fatalf("Could not find test-config.json file")
	}

	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	server := &Server{
		config:          config,
		scenarios:       make(map[string]TestScenario),
		scenariosByPath: make(map[string]TestScenario),
	}

	for _, scenario := range config.Scenarios {
		server.scenarios[scenario.ID] = scenario
		if scenario.Path != "" {
			server.scenariosByPath[scenario.Path] = scenario
		}
	}

	mux := http.NewServeMux()
	server.registerHTTPHandlers(mux)

	// Test direct scenario path access
	t.Run("direct scenario path /api/v1/test", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == 404 {
			t.Errorf("Got 404 for /api/v1/test. Response: %s", w.Body.String())
			t.Logf("Scenarios by path: %v", getScenarioPaths(server.scenariosByPath))
			t.Logf("Scenarios by ID: %v", getScenarioIDs(server.scenarios))
		}

		// Parse JSON response
		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err == nil {
			if response["path"] != "/api/v1/test" {
				t.Errorf("Expected path '/api/v1/test' in response, got %v", response["path"])
			}
		}
	})

	t.Run("direct scenario path /old/test", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/old/test", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == 404 {
			t.Errorf("Got 404 for /old/test. Response: %s", w.Body.String())
			t.Logf("Scenarios by path: %v", getScenarioPaths(server.scenariosByPath))
		}
	})
}

// Helper functions
func getScenarioIDs(scenarios map[string]TestScenario) []string {
	ids := make([]string, 0, len(scenarios))
	for id := range scenarios {
		ids = append(ids, id)
	}
	return ids
}

func getScenarioPaths(scenariosByPath map[string]TestScenario) []string {
	paths := make([]string, 0, len(scenariosByPath))
	for path := range scenariosByPath {
		paths = append(paths, path)
	}
	return paths
}


