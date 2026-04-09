package configloader

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestLoadBalancerFromStorage tests loading load balancer config from storage (runtime scenario)
func TestLoadBalancerFromStorage(t *testing.T) {
	// This is the exact JSON stored in PostgreSQL (from test fixtures)
	loadBalancerJSON := `{
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

	// Create mock storage with the config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"loadbalancer.test": []byte(loadBalancerJSON),
		},
	}

	// Create mock manager with proper settings
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

	// Create a request
	req := httptest.NewRequest("GET", "http://loadbalancer.test/", nil)

	// Load config using the same path as runtime
	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// This is the critical test - IsProxy() should return true
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for load balancer loaded from storage")
		t.Logf("Config ID: %s", cfg.ID)
		t.Logf("Config Hostname: %s", cfg.Hostname)
		
		// Access the action via reflection or type assertion
		// The action field is private, so we need to check via the public methods
		t.Logf("Transport() is nil: %v", cfg.Transport() == nil)
		t.Logf("Handler() is nil: %v", cfg.Handler() == nil)
	}

	// Verify Transport() is not nil
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil for load balancer")
	}
}

// TestGraphQLFromStorage tests loading GraphQL config from storage (runtime scenario)
func TestGraphQLFromStorage(t *testing.T) {
	// This is the exact JSON stored in PostgreSQL (from test fixtures)
	graphQLJSON := `{
		"id": "graphql",
		"hostname": "graphql.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "graphql",
			"url": "http://e2e-test-server:8092/graphql",
			"max_depth": 10,
			"max_complexity": 100,
			"enable_introspection": true,
			"enable_query_batching": true,
			"enable_query_deduplication": true
		}
	}`

	// Create mock storage with the config
	mockStore := &mockStorage{
		data: map[string][]byte{
			"graphql.test": []byte(graphQLJSON),
		},
	}

	// Create mock manager with proper settings
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

	// Create a request
	req := httptest.NewRequest("POST", "http://graphql.test/", nil)

	// Load config using the same path as runtime
	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// This is the critical test - IsProxy() should return true
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for GraphQL loaded from storage")
		t.Logf("Config ID: %s", cfg.ID)
		t.Logf("Config Hostname: %s", cfg.Hostname)
		t.Logf("Transport() is nil: %v", cfg.Transport() == nil)
	}

	// Verify Transport() is not nil
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil for GraphQL")
	}
}

