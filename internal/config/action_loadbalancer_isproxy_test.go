package config

import (
	"encoding/json"
	"testing"
)

// TestLoadBalancerIsProxy tests that IsProxy() returns true after Init() is called
func TestLoadBalancerIsProxy(t *testing.T) {
	configJSON := `{
		"type": "loadbalancer",
		"targets": [
			{
				"url": "http://backend1.example.com"
			}
		]
	}`

	// Load the config
	action, err := LoadLoadBalancerConfig([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load load balancer config: %v", err)
	}

	lbConfig, ok := action.(*LoadBalancerTypedConfig)
	if !ok {
		t.Fatalf("Expected LoadBalancerTypedConfig, got %T", action)
	}

	// Before Init(), IsProxy() should return false (transport not set)
	if lbConfig.IsProxy() {
		t.Error("IsProxy() should return false before Init() is called")
	}

	// Create a minimal config for Init()
	cfg := &Config{
		ID: "test-lb",
	}

	// Call Init() which should set the transport
	err = lbConfig.Init(cfg)
	if err != nil {
		t.Fatalf("Init() failed: %v", err)
	}

	// After Init(), IsProxy() should return true (transport is set)
	if !lbConfig.IsProxy() {
		t.Error("IsProxy() should return true after Init() is called")
	}

	// Verify transport is not nil
	if lbConfig.tr == nil {
		t.Error("Transport should be set after Init()")
	}
}

// TestLoadBalancerIsProxyWithConfig tests IsProxy() through the Config interface
func TestLoadBalancerIsProxyWithConfig(t *testing.T) {
	configJSON := `{
		"id": "test-lb",
		"hostname": "lb.test",
		"action": {
			"type": "loadbalancer",
			"targets": [
				{
					"url": "http://backend1.example.com"
				}
			]
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Config.IsProxy() should return true after unmarshaling (which calls Init())
	if !cfg.IsProxy() {
		t.Error("Config.IsProxy() should return true for load balancer after unmarshaling")
	}

	// Verify it uses proxy mode - IsProxy() should return true
	// This ensures ServeHTTP() uses proxy mode instead of handler mode
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for load balancer (should use proxy mode)")
	}

	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil for load balancer")
	}
}

