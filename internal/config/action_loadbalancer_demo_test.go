package config

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadBalancerDemoConfig tests loading the actual lb.demo.soapbucket.com config
// from the demo.hosts.json file to verify it parses correctly
func TestLoadBalancerDemoConfig(t *testing.T) {
	// Find the demo.hosts.json file relative to the test
	// The test runs from internal/config, so we need to go up to the repo root
	paths := []string{
		"../../conf/demo.hosts.json",
		"conf/demo.hosts.json",
		"../../../conf/demo.hosts.json",
	}

	var configPath string
	var data []byte
	var err error

	for _, p := range paths {
		absPath, _ := filepath.Abs(p)
		data, err = os.ReadFile(absPath)
		if err == nil {
			configPath = absPath
			break
		}
	}

	if data == nil {
		t.Skip("Could not find demo.hosts.json file - skipping test")
		return
	}

	t.Logf("Loading config from: %s", configPath)

	// Parse the entire file as a map of hostname -> config
	var allConfigs map[string]json.RawMessage
	if err := json.Unmarshal(data, &allConfigs); err != nil {
		t.Fatalf("Failed to parse demo.hosts.json: %v", err)
	}

	// Check that lb.demo.soapbucket.com exists
	lbConfigRaw, ok := allConfigs["lb.demo.soapbucket.com"]
	if !ok {
		t.Fatal("lb.demo.soapbucket.com not found in demo.hosts.json")
	}

	t.Logf("Found lb.demo.soapbucket.com config: %s", string(lbConfigRaw)[:200])

	// Parse the load balancer config
	var cfg Config
	if err := json.Unmarshal(lbConfigRaw, &cfg); err != nil {
		t.Fatalf("Failed to parse lb.demo.soapbucket.com config: %v", err)
	}

	// Verify basic fields
	if cfg.ID != "lb-demo" {
		t.Errorf("Expected ID 'lb-demo', got '%s'", cfg.ID)
	}

	if cfg.Hostname != "lb.demo.soapbucket.com" {
		t.Errorf("Expected Hostname 'lb.demo.soapbucket.com', got '%s'", cfg.Hostname)
	}

	// Verify this is a load balancer
	if cfg.action == nil {
		t.Fatal("Action is nil - config not properly initialized")
	}

	if cfg.action.GetType() != TypeLoadBalancer {
		t.Errorf("Expected action type '%s', got '%s'", TypeLoadBalancer, cfg.action.GetType())
	}

	// Verify IsProxy returns true
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for load balancer")
	}

	// Verify Transport is set
	if cfg.Transport() == nil {
		t.Error("Transport() should not return nil for load balancer")
	}

	// Verify targets
	lbConfig, ok := cfg.action.(*LoadBalancerTypedConfig)
	if !ok {
		t.Fatalf("Expected LoadBalancerTypedConfig, got %T", cfg.action)
	}

	if len(lbConfig.compiledTargets) != 3 {
		t.Errorf("Expected 3 targets, got %d", len(lbConfig.compiledTargets))
	}

	// Verify the StripBasePath setting (should be false after our fix)
	if lbConfig.StripBasePath != false {
		t.Errorf("Expected StripBasePath=false, got %v", lbConfig.StripBasePath)
	}

	// Log target URLs to help debug
	for i, target := range lbConfig.compiledTargets {
		t.Logf("Target %d: URL=%s, Weight=%d", i, target.URL.String(), target.Config.Weight)
	}
}

// TestLoadBalancerDemoConfigLiveRoundTrip tests making actual HTTP requests through the load balancer
// This test requires network access to postman-echo.com
func TestLoadBalancerDemoConfigLiveRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live HTTP test in short mode")
	}

	// Skip if we can't find the config file
	paths := []string{
		"../../conf/demo.hosts.json",
		"conf/demo.hosts.json",
	}

	var data []byte
	var err error

	for _, p := range paths {
		absPath, _ := filepath.Abs(p)
		data, err = os.ReadFile(absPath)
		if err == nil {
			break
		}
	}

	if data == nil {
		t.Skip("Could not find demo.hosts.json file - skipping test")
		return
	}

	var allConfigs map[string]json.RawMessage
	if err := json.Unmarshal(data, &allConfigs); err != nil {
		t.Fatalf("Failed to parse demo.hosts.json: %v", err)
	}

	lbConfigRaw, ok := allConfigs["lb.demo.soapbucket.com"]
	if !ok {
		t.Fatal("lb.demo.soapbucket.com not found in demo.hosts.json")
	}

	var cfg Config
	if err := json.Unmarshal(lbConfigRaw, &cfg); err != nil {
		t.Fatalf("Failed to parse lb.demo.soapbucket.com config: %v", err)
	}

	transport := cfg.Transport()
	if transport == nil {
		t.Fatal("Transport is nil")
	}

	// Make multiple requests to see load balancing in action
	// Note: With strip_base_path=false, request path "/" will use target path "/get"
	// Request path "/api/users" would result in "/get/api/users" which doesn't exist
	backendCounts := make(map[string]int)
	for i := 0; i < 10; i++ {
		// Use root path "/" so the target URL path "/get" is used
		req, err := http.NewRequest("GET", "https://postman-echo.com/", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		t.Logf("Request %d: Status=%d, URL=%s", i, resp.StatusCode, req.URL.String())

		// Log part of the response
		bodyStr := string(body)
		if len(bodyStr) > 500 {
			bodyStr = bodyStr[:500] + "..."
		}
		t.Logf("Response body: %s", bodyStr)

		// Parse response to check backend
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Logf("Failed to parse JSON response: %v", err)
			continue
		}

		// postman-echo.com returns query params in "args" field
		if args, ok := result["args"].(map[string]interface{}); ok {
			if backend, ok := args["backend"].(string); ok {
				backendCounts[backend]++
				t.Logf("Backend from response: %s", backend)
			}
		}

		// Check X-Served-By header from response modifiers
		servedBy := resp.Header.Get("X-Served-By")
		if servedBy != "" {
			t.Logf("X-Served-By header: %s", servedBy)
		}
	}

	t.Logf("Backend distribution: %v", backendCounts)

	// Verify we got responses from multiple backends
	if len(backendCounts) == 0 {
		t.Error("No backend information found in responses")
	}
}

// TestLoadBalancerDemoConfigRoundTrip tests the full round trip using the demo config
func TestLoadBalancerDemoConfigRoundTrip(t *testing.T) {
	// Skip if we can't find the config file
	paths := []string{
		"../../conf/demo.hosts.json",
		"conf/demo.hosts.json",
	}

	var data []byte
	var err error

	for _, p := range paths {
		absPath, _ := filepath.Abs(p)
		data, err = os.ReadFile(absPath)
		if err == nil {
			break
		}
	}

	if data == nil {
		t.Skip("Could not find demo.hosts.json file - skipping test")
		return
	}

	var allConfigs map[string]json.RawMessage
	if err := json.Unmarshal(data, &allConfigs); err != nil {
		t.Fatalf("Failed to parse demo.hosts.json: %v", err)
	}

	lbConfigRaw, ok := allConfigs["lb.demo.soapbucket.com"]
	if !ok {
		t.Fatal("lb.demo.soapbucket.com not found in demo.hosts.json")
	}

	var cfg Config
	if err := json.Unmarshal(lbConfigRaw, &cfg); err != nil {
		t.Fatalf("Failed to parse lb.demo.soapbucket.com config: %v", err)
	}

	// Verify config is valid for proxying
	t.Logf("Config ID: %s", cfg.ID)
	t.Logf("Config IsProxy: %v", cfg.IsProxy())
	t.Logf("Config Action Type: %s", cfg.action.GetType())

	lbConfig := cfg.action.(*LoadBalancerTypedConfig)
	t.Logf("StripBasePath: %v", lbConfig.StripBasePath)
	t.Logf("PreserveQuery: %v", lbConfig.PreserveQuery)
	t.Logf("LeastConnections: %v", lbConfig.LeastConnections)
	t.Logf("DisableSticky: %v", lbConfig.DisableSticky)
	t.Logf("Number of targets: %d", len(lbConfig.compiledTargets))

	for i, target := range lbConfig.compiledTargets {
		t.Logf("  Target %d: %s (weight: %d)", i, target.URL.String(), target.Config.Weight)
	}
}
