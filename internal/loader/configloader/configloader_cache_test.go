package configloader

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestLoadBalancerCacheReload tests that configs are correctly initialized when reloaded from cache
func TestLoadBalancerCacheReload(t *testing.T) {
	// Reset cache to ensure clean state
	resetCache()

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
				}
			]
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"loadbalancer.test": []byte(loadBalancerJSON),
		},
	}

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

	req := httptest.NewRequest("GET", "http://loadbalancer.test/", nil)

	// First load - should load from storage and initialize
	cfg1, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if !cfg1.IsProxy() {
		t.Error("First load: IsProxy() should return true")
	}

	// Second load - should come from cache
	cfg2, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config from cache: %v", err)
	}

	// This is the critical test - cached config should also have IsProxy() = true
	if !cfg2.IsProxy() {
		t.Error("Cached config: IsProxy() should return true")
		t.Logf("Config ID: %s", cfg2.ID)
		t.Logf("Transport() is nil: %v", cfg2.Transport() == nil)
	}

	// Verify they're the same instance (from cache)
	if cfg1 != cfg2 {
		t.Error("Expected same config instance from cache")
	}
}

// TestGraphQLCacheReload tests that GraphQL configs are correctly initialized when reloaded from cache
func TestGraphQLCacheReload(t *testing.T) {
	// Reset cache to ensure clean state
	resetCache()

	graphQLJSON := `{
		"id": "graphql",
		"hostname": "graphql.test",
			"workspace_id": "test-workspace",
		"action": {
			"type": "graphql",
			"url": "http://e2e-test-server:8092/graphql"
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"graphql.test": []byte(graphQLJSON),
		},
	}

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

	req := httptest.NewRequest("POST", "http://graphql.test/", nil)

	// First load - should load from storage and initialize
	cfg1, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if !cfg1.IsProxy() {
		t.Error("First load: IsProxy() should return true")
	}

	// Second load - should come from cache
	cfg2, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config from cache: %v", err)
	}

	// This is the critical test - cached config should also have IsProxy() = true
	if !cfg2.IsProxy() {
		t.Error("Cached config: IsProxy() should return true")
		t.Logf("Config ID: %s", cfg2.ID)
		t.Logf("Transport() is nil: %v", cfg2.Transport() == nil)
	}
}

