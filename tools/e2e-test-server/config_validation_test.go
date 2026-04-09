package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfigAndValidateApiV1Test loads the actual config file used by Docker
// and validates that /api/v1/test endpoint works correctly
func TestLoadConfigAndValidateApiV1Test(t *testing.T) {
	// Find the config file - try multiple locations
	configPaths := []string{
		"test/fixtures/test-server-config.json",       // Relative from tools/e2e-test-server
		"../test/fixtures/test-server-config.json",    // From tools/e2e-test-server
		"../../test/fixtures/test-server-config.json", // From proxy root
		"test-server-config.json",                     // Current dir
	}

	var configPath string
	for _, path := range configPaths {
		absPath, _ := filepath.Abs(path)
		if _, err := os.Stat(path); err == nil {
			configPath = path
			t.Logf("Found config at: %s (abs: %s)", path, absPath)
			break
		}
	}

	if configPath == "" {
		// Try absolute path from current working directory
		wd, _ := os.Getwd()
		absPath := filepath.Join(wd, "test/fixtures/test-server-config.json")
		if _, err := os.Stat(absPath); err == nil {
			configPath = absPath
			t.Logf("Found config at absolute path: %s", absPath)
		}
	}

	if configPath == "" {
		t.Fatalf("Could not find test-server-config.json. Tried: %v", configPaths)
	}

	// Load config - need to handle body as both string and map
	t.Logf("Loading config from: %s", configPath)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	// Use json.RawMessage to handle body as either string or map
	var rawConfig struct {
		Name        string                 `json:"name"`
		Description string                 `json:"description"`
		Scenarios   json.RawMessage        `json:"scenarios"`
		Defaults    map[string]interface{} `json:"defaults"`
	}

	if err := json.Unmarshal(data, &rawConfig); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Parse scenarios with flexible body handling
	var scenarios []struct {
		ID       string          `json:"id"`
		Name     string          `json:"name"`
		Path     string          `json:"path"`
		Method   string          `json:"method"`
		Request  json.RawMessage `json:"request"`
		Response struct {
			Status  int               `json:"status"`
			Headers map[string]string `json:"headers"`
			Body    json.RawMessage   `json:"body"` // Can be string or map
			BodyRaw string            `json:"body_raw"`
			Delay   int               `json:"delay"`
		} `json:"response"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := json.Unmarshal(rawConfig.Scenarios, &scenarios); err != nil {
		t.Fatalf("Failed to unmarshal scenarios: %v", err)
	}

	// Convert to TestConfig format
	config := &TestConfig{
		Name:        rawConfig.Name,
		Description: rawConfig.Description,
		Defaults:    rawConfig.Defaults,
		Scenarios:   make([]TestScenario, len(scenarios)),
	}

	for i, s := range scenarios {
		config.Scenarios[i] = TestScenario{
			ID:       s.ID,
			Name:     s.Name,
			Path:     s.Path,
			Method:   s.Method,
			Metadata: s.Metadata,
		}

		// Handle response - convert body from string to map if needed
		config.Scenarios[i].Response = ResponseConfig{
			Status:  s.Response.Status,
			Headers: s.Response.Headers,
			BodyRaw: s.Response.BodyRaw,
			Delay:   s.Response.Delay,
		}

		// If body_raw is not set, try to parse body
		if s.Response.BodyRaw == "" && len(s.Response.Body) > 0 {
			// Try as map first
			var bodyMap map[string]interface{}
			if err := json.Unmarshal(s.Response.Body, &bodyMap); err == nil {
				config.Scenarios[i].Response.Body = bodyMap
			} else {
				// If not a map, treat as raw string
				var bodyStr string
				if err := json.Unmarshal(s.Response.Body, &bodyStr); err == nil {
					config.Scenarios[i].Response.BodyRaw = bodyStr
				}
			}
		}
	}

	if config == nil {
		t.Fatalf("Config is nil after loading")
	}

	t.Logf("✓ Config loaded successfully")
	t.Logf("  - Config name: %s", config.Name)
	t.Logf("  - Total scenarios: %d", len(config.Scenarios))

	// Verify api-v1-test scenario exists
	var apiV1Scenario *TestScenario
	for i := range config.Scenarios {
		if config.Scenarios[i].ID == "api-v1-test" {
			apiV1Scenario = &config.Scenarios[i]
			break
		}
	}

	if apiV1Scenario == nil {
		t.Fatalf("Scenario 'api-v1-test' not found in config")
	}

	t.Logf("✓ Found api-v1-test scenario")
	t.Logf("  - Path: %s", apiV1Scenario.Path)
	t.Logf("  - Method: %s", apiV1Scenario.Method)

	if apiV1Scenario.Path != "/api/v1/test" {
		t.Errorf("Expected path '/api/v1/test', got '%s'", apiV1Scenario.Path)
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

	t.Logf("✓ Scenarios indexed")
	t.Logf("  - By ID: %d scenarios", len(server.scenarios))
	t.Logf("  - By path: %d scenarios", len(server.scenariosByPath))

	// Verify scenario is indexed by path
	scenarioByPath, exists := server.scenariosByPath["/api/v1/test"]
	if !exists {
		t.Errorf("Scenario not found in scenariosByPath map")
		t.Logf("Available paths: %v", getPaths(server.scenariosByPath))
		return
	}

	if scenarioByPath.ID != "api-v1-test" {
		t.Errorf("Scenario at path '/api/v1/test' has ID '%s', expected 'api-v1-test'", scenarioByPath.ID)
	}

	t.Logf("✓ Scenario indexed correctly by path")

	// Create mux and register handlers exactly as main() does
	mux := http.NewServeMux()
	server.registerHTTPHandlers(mux)

	t.Logf("✓ HTTP handlers registered")

	// Test the endpoint
	t.Run("GET /api/v1/test", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		w := httptest.NewRecorder()

		t.Logf("Making request: GET /api/v1/test")
		mux.ServeHTTP(w, req)

		t.Logf("Response status: %d", w.Code)
		t.Logf("Response body: %s", w.Body.String())
		t.Logf("Response headers: %v", w.Header())

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
			t.Errorf("Response body: %s", w.Body.String())
			return
		}

		// Parse and validate JSON response
		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Errorf("Failed to parse JSON response: %v. Body: %s", err, w.Body.String())
			return
		}

		// Validate response structure
		if response["status"] != "success" {
			t.Errorf("Expected status 'success', got '%v'", response["status"])
		}

		if response["path"] != "/api/v1/test" {
			t.Errorf("Expected path '/api/v1/test', got '%v'", response["path"])
		}

		if response["message"] != "API v1 test endpoint" {
			t.Errorf("Expected message 'API v1 test endpoint', got '%v'", response["message"])
		}

		t.Logf("✓ Response validated successfully")
		t.Logf("  - Status: %v", response["status"])
		t.Logf("  - Path: %v", response["path"])
		t.Logf("  - Message: %v", response["message"])
	})

	// Also test that handleScenarioByPath works directly
	t.Run("Direct handleScenarioByPath", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		w := httptest.NewRecorder()

		t.Logf("Testing handleScenarioByPath directly")
		server.handleScenarioByPath(w, req)

		t.Logf("Response status: %d", w.Code)
		t.Logf("Response body: %s", w.Body.String())

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})

	// Test handleRoot delegation
	t.Run("handleRoot delegates to scenario", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		w := httptest.NewRecorder()

		t.Logf("Testing handleRoot delegation")
		server.handleRoot(w, req)

		t.Logf("Response status: %d", w.Code)
		t.Logf("Response body: %s", w.Body.String())

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
}

// Helper function to get all paths from scenariosByPath map
func getPaths(scenariosByPath map[string]TestScenario) []string {
	paths := make([]string, 0, len(scenariosByPath))
	for path := range scenariosByPath {
		paths = append(paths, path)
	}
	return paths
}

// TestConfigFileExists validates that the config file exists and is valid JSON
func TestConfigFileExists(t *testing.T) {
	configPaths := []string{
		"test/fixtures/test-server-config.json",
		"../test/fixtures/test-server-config.json",
		"../../test/fixtures/test-server-config.json",
	}

	var configPath string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}

	if configPath == "" {
		t.Fatalf("Config file not found. Tried: %v", configPaths)
	}

	t.Logf("Found config file: %s", configPath)

	// Read and validate JSON - use loadConfig which handles flexible body types
	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	t.Logf("Config file is valid JSON")
	t.Logf("  - Name: %s", config.Name)
	t.Logf("  - Scenarios: %d", len(config.Scenarios))

	// Check for api-v1-test scenario
	found := false
	for _, scenario := range config.Scenarios {
		if scenario.ID == "api-v1-test" {
			found = true
			t.Logf("  - Found api-v1-test scenario with path: %s", scenario.Path)
			if scenario.Path != "/api/v1/test" {
				t.Errorf("Expected path '/api/v1/test', got '%s'", scenario.Path)
			}
			break
		}
	}

	if !found {
		t.Errorf("api-v1-test scenario not found in config file")
		t.Logf("Available scenario IDs:")
		for _, scenario := range config.Scenarios {
			t.Logf("  - %s (path: %s)", scenario.ID, scenario.Path)
		}
	}
}
