package config

import (
	"testing"
)

func TestLoadBalancerConfig_DiscoveryParsing(t *testing.T) {
	data := []byte(`{
		"type": "load_balancer",
		"algorithm": "round_robin",
		"discovery": {
			"type": "dns_srv",
			"service": "_http._tcp.api.example.com",
			"refresh_interval": "30s"
		}
	}`)

	cfg, err := LoadLoadBalancerConfig(data)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	typed, ok := cfg.(*LoadBalancerTypedConfig)
	if !ok {
		t.Fatal("expected *LoadBalancerTypedConfig")
	}

	if typed.Discovery == nil {
		t.Fatal("expected discovery config to be parsed")
	}
	if typed.Discovery.Type != "dns_srv" {
		t.Errorf("expected dns_srv, got %s", typed.Discovery.Type)
	}
	if typed.Discovery.Service != "_http._tcp.api.example.com" {
		t.Errorf("expected service name, got %s", typed.Discovery.Service)
	}
}

func TestLoadBalancerConfig_DiscoveryValidation_ConsulRejected(t *testing.T) {
	data := []byte(`{
		"type": "load_balancer",
		"discovery": {
			"type": "consul",
			"service": "my-service"
		}
	}`)

	_, err := LoadLoadBalancerConfig(data)
	if err == nil {
		t.Fatal("expected error for consul discovery type in OSS")
	}
}

func TestLoadBalancerConfig_DiscoveryValidation_MissingService(t *testing.T) {
	data := []byte(`{
		"type": "load_balancer",
		"discovery": {
			"type": "dns_srv"
		}
	}`)

	_, err := LoadLoadBalancerConfig(data)
	if err == nil {
		t.Fatal("expected error for dns_srv without service name")
	}
}

func TestLoadBalancerConfig_NoTargetsWithDiscovery(t *testing.T) {
	// Empty targets should be OK when discovery is configured
	data := []byte(`{
		"type": "load_balancer",
		"discovery": {
			"type": "dns_srv",
			"service": "_http._tcp.api.example.com"
		}
	}`)

	_, err := LoadLoadBalancerConfig(data)
	if err != nil {
		t.Fatalf("should allow empty targets with discovery: %v", err)
	}
}

func TestLoadBalancerConfig_NoTargetsNoDiscovery(t *testing.T) {
	// Empty targets without discovery should fail
	data := []byte(`{
		"type": "load_balancer"
	}`)

	_, err := LoadLoadBalancerConfig(data)
	if err == nil {
		t.Fatal("should reject empty targets without discovery")
	}
}
