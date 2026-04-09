package config

import (
	"encoding/json"
	"testing"
)

// TestLoadBalancerE2EConfig tests the exact config from the E2E test fixtures
// This reproduces the issue where load balancer returns 404 instead of proxying
func TestLoadBalancerE2EConfig(t *testing.T) {
	// This is the exact config from test/fixtures/origins/11-loadbalancer.json
	configJSON := `{
		"id": "loadbalancer",
		"hostname": "loadbalancer.test",
		"action": {
			"type": "loadbalancer",
			"targets": [
				{
					"url": "http://e2e-test-server:8090",
					"weight": 50
				},
				{
					"url": "http://e2e-test-server:8090",
					"weight": 50
				}
			],
			"round_robin": true,
			"disable_sticky": false,
			"sticky_cookie_name": "_sb.l"
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify IsProxy() returns true (this was the issue)
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for load balancer - this is the bug!")
		t.Logf("LoadBalancerTypedConfig.tr = %v", cfg.action.(*LoadBalancerTypedConfig).tr)
	}

	// Verify Transport() is not nil
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil for load balancer")
	}

	// Verify the config can handle the request (should use proxy mode, not handler mode)
	if !cfg.IsProxy() {
		t.Error("Config should be in proxy mode, not handler mode")
	}

	// Test that we can get a rewrite function
	rewriteFn := cfg.Rewrite()
	if rewriteFn == nil {
		t.Error("Rewrite() should not return nil for load balancer")
	}

	// Test that we can get a transport function
	if transport == nil {
		t.Error("Transport() should not return nil for load balancer")
	}

	// Verify the action type
	if cfg.action.GetType() != TypeLoadBalancer {
		t.Errorf("Expected action type %s, got %s", TypeLoadBalancer, cfg.action.GetType())
	}
}

// TestLoadBalancerHandlerReturnsNil tests that Handler() returns nil
// so that Config.Handler() creates a default handler that checks IsProxy()
func TestLoadBalancerHandlerReturnsNil(t *testing.T) {
	configJSON := `{
		"type": "loadbalancer",
		"targets": [
			{
				"url": "http://backend1.example.com"
			}
		]
	}`

	action, err := LoadLoadBalancerConfig([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load load balancer config: %v", err)
	}

	lbConfig, ok := action.(*LoadBalancerTypedConfig)
	if !ok {
		t.Fatalf("Expected LoadBalancerTypedConfig, got %T", action)
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

	// Handler() should return nil so Config.Handler() can check IsProxy()
	handler := lbConfig.Handler()
	if handler != nil {
		t.Error("Handler() should return nil for load balancer (uses proxy mode via IsProxy())")
	}

	// But IsProxy() should return true
	if !lbConfig.IsProxy() {
		t.Error("IsProxy() should return true after Init() sets transport")
	}
}

