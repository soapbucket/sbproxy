package config

import (
	"encoding/json"
	"testing"
)

// TestLoadBalancerLoadFromStorage simulates loading a load balancer config from storage
// This reproduces the exact path used when loading from PostgreSQL storage
func TestLoadBalancerLoadFromStorage(t *testing.T) {
	// This simulates the JSON bytes that come from storage.Get()
	configJSON := `{
		"id": "loadbalancer",
		"hostname": "loadbalancer.test",
		"workspace_id": "test-workspace",
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

	// Use config.Load() which is what configloader uses
	cfg, err := Load([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify IsProxy() returns true
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for load balancer after Load()")
		t.Logf("Config ID: %s", cfg.ID)
		t.Logf("Action type: %s", cfg.action.GetType())
		
		// Check if it's a LoadBalancerTypedConfig
		if lbConfig, ok := cfg.action.(*LoadBalancerTypedConfig); ok {
			t.Logf("LoadBalancerTypedConfig.tr is nil: %v", lbConfig.tr == nil)
			t.Logf("LoadBalancerTypedConfig.compiledTargets count: %d", len(lbConfig.compiledTargets))
		}
	}

	// Verify Transport() is not nil
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil for load balancer")
	}
}

// TestLoadBalancerUnmarshalJSON tests UnmarshalJSON directly
func TestLoadBalancerUnmarshalJSON(t *testing.T) {
	configJSON := `{
		"id": "loadbalancer",
		"hostname": "loadbalancer.test",
		"workspace_id": "test-workspace",
		"action": {
			"type": "loadbalancer",
			"targets": [
				{
					"url": "http://e2e-test-server:8090",
					"weight": 50
				}
			]
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify IsProxy() returns true
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for load balancer after UnmarshalJSON()")
		t.Logf("Config ID: %s", cfg.ID)
		t.Logf("Action type: %s", cfg.action.GetType())
		
		// Check if it's a LoadBalancerTypedConfig
		if lbConfig, ok := cfg.action.(*LoadBalancerTypedConfig); ok {
			t.Logf("LoadBalancerTypedConfig.tr is nil: %v", lbConfig.tr == nil)
			t.Logf("LoadBalancerTypedConfig.compiledTargets count: %d", len(lbConfig.compiledTargets))
		}
	}
}

