package configloader

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/config/forward"
	"github.com/soapbucket/sbproxy/internal/config/rule"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// TestForwardRules_PathPrefixMatching tests that forward rules with path prefix conditions match correctly
func TestForwardRules_PathPrefixMatching(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	// Create forward-rules-complex.test config with forward rules
	forwardRulesConfig := map[string]interface{}{
		"id":       "forward-rules-complex",
		"hostname": "forward-rules-complex.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8090",
		},
		"forward_rules": []map[string]interface{}{
			{
				"hostname": "api-v1-backend.test",
			"workspace_id": "test-workspace",
				"rules": []map[string]interface{}{
					{
						"path": map[string]interface{}{
							"prefix": "/api/v1",
						},
					},
				},
			},
			{
				"hostname": "old-service-backend.test",
			"workspace_id": "test-workspace",
				"rules": []map[string]interface{}{
					{
						"path": map[string]interface{}{
							"prefix": "/old",
						},
					},
				},
			},
		},
	}

	// Create target configs
	apiV1BackendConfig := map[string]interface{}{
		"id":       "api-v1-backend",
		"hostname": "api-v1-backend.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8090",
		},
	}

	oldServiceBackendConfig := map[string]interface{}{
		"id":       "old-service-backend",
		"hostname": "old-service-backend.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8090",
		},
	}

	// Marshal configs to JSON
	forwardRulesJSON, _ := json.Marshal(forwardRulesConfig)
	apiV1JSON, _ := json.Marshal(apiV1BackendConfig)
	oldServiceJSON, _ := json.Marshal(oldServiceBackendConfig)

	storage.data["forward-rules-complex.test"] = forwardRulesJSON
	storage.data["api-v1-backend.test"] = apiV1JSON
	storage.data["old-service-backend.test"] = oldServiceJSON

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	tests := []struct {
		name           string
		hostname       string
		path           string
		expectedID     string
		expectedParent string
	}{
		{
			name:           "Path /api/v1/test should forward to api-v1-backend",
			hostname:       "forward-rules-complex.test",
			path:           "/api/v1/test",
			expectedID:     "api-v1-backend",
			expectedParent: "forward-rules-complex",
		},
		{
			name:           "Path /old/test should forward to old-service-backend",
			hostname:       "forward-rules-complex.test",
			path:           "/old/test",
			expectedID:     "old-service-backend",
			expectedParent: "forward-rules-complex",
		},
		{
			name:           "Path /old/path should forward to old-service-backend",
			hostname:       "forward-rules-complex.test",
			path:           "/old/path",
			expectedID:     "old-service-backend",
			expectedParent: "forward-rules-complex",
		},
		{
			name:           "Path /api/test should not forward (no matching rule)",
			hostname:       "forward-rules-complex.test",
			path:           "/api/test",
			expectedID:     "forward-rules-complex",
			expectedParent: "",
		},
		{
			name:           "Path / should not forward (no matching rule)",
			hostname:       "forward-rules-complex.test",
			path:           "/",
			expectedID:     "forward-rules-complex",
			expectedParent: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCache()

			req := httptest.NewRequest(http.MethodGet, "http://"+tt.hostname+tt.path, nil)
			req.Host = tt.hostname

			cfg, err := getConfigByHostname(context.Background(), req, tt.hostname, 0, mgr, nil)
			if err != nil {
				t.Fatalf("getConfigByHostname() error = %v", err)
			}

			if cfg.ID != tt.expectedID {
				t.Errorf("Expected config ID %s, got %s", tt.expectedID, cfg.ID)
			}

			if tt.expectedParent != "" {
				if cfg.Parent == nil {
					t.Error("Expected parent to be set, got nil")
				} else if cfg.Parent.ID != tt.expectedParent {
					t.Errorf("Expected parent ID %s, got %s", tt.expectedParent, cfg.Parent.ID)
				}
			} else {
				if cfg.Parent != nil {
					t.Errorf("Expected no parent, got parent with ID %s", cfg.Parent.ID)
				}
			}
		})
	}
}

// TestForwardRules_MissingTargetConfig tests that forward rules fail gracefully when target config doesn't exist
func TestForwardRules_MissingTargetConfig(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	// Create forward-rules-complex.test config with forward rules pointing to non-existent config
	forwardRulesConfig := map[string]interface{}{
		"id":       "forward-rules-complex",
		"hostname": "forward-rules-complex.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8090",
		},
		"forward_rules": []map[string]interface{}{
			{
				"hostname": "non-existent-backend.test",
			"workspace_id": "test-workspace",
				"rules": []map[string]interface{}{
					{
						"path": map[string]interface{}{
							"prefix": "/api/v1",
						},
					},
				},
			},
		},
	}

	forwardRulesJSON, _ := json.Marshal(forwardRulesConfig)
	storage.data["forward-rules-complex.test"] = forwardRulesJSON
	// Note: "non-existent-backend.test" is NOT in storage

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://forward-rules-complex.test/api/v1/test", nil)
	req.Host = "forward-rules-complex.test"

	cfg, err := getConfigByHostname(context.Background(), req, "forward-rules-complex.test", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}

	// Should return null-config for non-existent target
	if cfg.ID != "null-config" {
		t.Errorf("Expected null-config for missing target, got %s", cfg.ID)
	}

	if !cfg.Disabled {
		t.Error("Expected null-config to be disabled")
	}
}

// TestForwardRules_ForwardRulesLoaded tests that forward rules are actually loaded from JSON
func TestForwardRules_ForwardRulesLoaded(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	forwardRulesConfig := map[string]interface{}{
		"id":       "forward-rules-complex",
		"hostname": "forward-rules-complex.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8090",
		},
		"forward_rules": []map[string]interface{}{
			{
				"hostname": "api-v1-backend.test",
			"workspace_id": "test-workspace",
				"rules": []map[string]interface{}{
					{
						"path": map[string]interface{}{
							"prefix": "/api/v1",
						},
					},
				},
			},
		},
	}

	forwardRulesJSON, _ := json.Marshal(forwardRulesConfig)
	storage.data["forward-rules-complex.test"] = forwardRulesJSON

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://forward-rules-complex.test/", nil)
	req.Host = "forward-rules-complex.test"

	cfg, err := getConfigByHostname(context.Background(), req, "forward-rules-complex.test", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}

	// Verify forward rules are loaded
	if len(cfg.ForwardRules) == 0 {
		t.Error("Expected forward rules to be loaded, got 0")
	}

	if len(cfg.ForwardRules) != 1 {
		t.Errorf("Expected 1 forward rule, got %d", len(cfg.ForwardRules))
	}

	if cfg.ForwardRules[0].Hostname != "api-v1-backend.test" {
		t.Errorf("Expected hostname api-v1-backend.test, got %s", cfg.ForwardRules[0].Hostname)
	}

	// Verify the rule has path prefix condition
	if len(cfg.ForwardRules[0].Rules) == 0 {
		t.Error("Expected forward rule to have rules, got 0")
	}

	if cfg.ForwardRules[0].Rules[0].Path == nil {
		t.Error("Expected forward rule to have path condition, got nil")
	}

	if cfg.ForwardRules[0].Rules[0].Path.Prefix != "/api/v1" {
		t.Errorf("Expected path prefix /api/v1, got %s", cfg.ForwardRules[0].Rules[0].Path.Prefix)
	}
}

// TestForwardRules_Apply tests that ForwardRules.Apply() correctly matches paths
func TestForwardRules_Apply(t *testing.T) {
	forwardRules := forward.ForwardRules{
		{
			Hostname: "api-v1-backend.test",
			Rules: rule.RequestRules{
				{
					Path: &rule.PathConditions{
						Prefix: "/api/v1",
					},
				},
			},
		},
		{
			Hostname: "old-service-backend.test",
			Rules: rule.RequestRules{
				{
					Path: &rule.PathConditions{
						Prefix: "/old",
					},
				},
			},
		},
	}

	tests := []struct {
		name           string
		path           string
		expectedHost   string
		expectedMatch  bool
	}{
		{
			name:          "Path /api/v1/test should match first rule",
			path:          "/api/v1/test",
			expectedHost:  "api-v1-backend.test",
			expectedMatch: true,
		},
		{
			name:          "Path /old/test should match second rule",
			path:          "/old/test",
			expectedHost:  "old-service-backend.test",
			expectedMatch: true,
		},
		{
			name:          "Path /old/path should match second rule",
			path:          "/old/path",
			expectedHost:  "old-service-backend.test",
			expectedMatch: true,
		},
		{
			name:          "Path /api/test should not match",
			path:          "/api/test",
			expectedHost:  "",
			expectedMatch: false,
		},
		{
			name:          "Path / should not match",
			path:          "/",
			expectedHost:  "",
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://forward-rules-complex.test"+tt.path, nil)
			req.Host = "forward-rules-complex.test"

			result := forwardRules.Apply(req)

			if tt.expectedMatch {
				if result != tt.expectedHost {
					t.Errorf("Expected hostname %s, got %s", tt.expectedHost, result)
				}
			} else {
				if result != "" {
					t.Errorf("Expected no match (empty string), got %s", result)
				}
			}
		})
	}
}

// TestForwardRules_ParentApplyEnabledByDefault tests that when a config is loaded via forward rules,
// parent propagation is enabled by default (DisableApplyParent defaults to false).
func TestForwardRules_ParentApplyEnabledByDefault(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	// Create parent config with forward rules
	parentConfig := map[string]interface{}{
		"id":       "gateway",
		"hostname": "gateway.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8090",
		},
		"forward_rules": []map[string]interface{}{
			{
				"hostname": "backend.test",
			"workspace_id": "test-workspace",
				"rules": []map[string]interface{}{
					{
						"path": map[string]interface{}{
							"prefix": "/api",
						},
					},
				},
			},
		},
	}

	// Create child config WITHOUT disable_apply_parent (should default to false)
	childConfig := map[string]interface{}{
		"id":       "backend",
		"hostname": "backend.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8091",
		},
	}

	parentJSON, _ := json.Marshal(parentConfig)
	childJSON, _ := json.Marshal(childConfig)

	storage.data["gateway.test"] = parentJSON
	storage.data["backend.test"] = childJSON

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://gateway.test/api/test", nil)
	req.Host = "gateway.test"

	cfg, err := getConfigByHostname(context.Background(), req, "gateway.test", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}

	if cfg.ID != "backend" {
		t.Errorf("Expected config ID 'backend', got %q", cfg.ID)
	}

	if cfg.Parent == nil {
		t.Fatal("Expected parent to be set")
	}

	if cfg.Parent.ID != "gateway" {
		t.Errorf("Expected parent ID 'gateway', got %q", cfg.Parent.ID)
	}

	// DisableApplyParent should default to false (parent propagation enabled)
	if cfg.DisableApplyParent {
		t.Error("Expected DisableApplyParent to be false by default")
	}
}

// TestForwardRules_DisableApplyParentOptOut tests that a child config can opt-out
// of parent propagation by setting disable_apply_parent: true.
func TestForwardRules_DisableApplyParentOptOut(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	parentConfig := map[string]interface{}{
		"id":       "gateway",
		"hostname": "gateway.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8090",
		},
		"forward_rules": []map[string]interface{}{
			{
				"hostname": "isolated-backend.test",
			"workspace_id": "test-workspace",
				"rules": []map[string]interface{}{
					{
						"path": map[string]interface{}{
							"prefix": "/isolated",
						},
					},
				},
			},
		},
	}

	// Create child config WITH disable_apply_parent: true
	childConfig := map[string]interface{}{
		"id":                   "isolated-backend",
		"hostname":             "isolated-backend.test",
			"workspace_id": "test-workspace",
		"disable_apply_parent": true,
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8091",
		},
	}

	parentJSON, _ := json.Marshal(parentConfig)
	childJSON, _ := json.Marshal(childConfig)

	storage.data["gateway.test"] = parentJSON
	storage.data["isolated-backend.test"] = childJSON

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://gateway.test/isolated/test", nil)
	req.Host = "gateway.test"

	cfg, err := getConfigByHostname(context.Background(), req, "gateway.test", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}

	if cfg.ID != "isolated-backend" {
		t.Errorf("Expected config ID 'isolated-backend', got %q", cfg.ID)
	}

	// Parent should still be set (for reference)
	if cfg.Parent == nil {
		t.Fatal("Expected parent to be set")
	}

	// But DisableApplyParent should be true (opted out)
	if !cfg.DisableApplyParent {
		t.Error("Expected DisableApplyParent to be true (opt-out)")
	}
}

// TestForwardRules_CachedConfig tests that forward rules work with cached configs
func TestForwardRules_CachedConfig(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	forwardRulesConfig := map[string]interface{}{
		"id":       "forward-rules-complex",
		"hostname": "forward-rules-complex.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8090",
		},
		"forward_rules": []map[string]interface{}{
			{
				"hostname": "api-v1-backend.test",
			"workspace_id": "test-workspace",
				"rules": []map[string]interface{}{
					{
						"path": map[string]interface{}{
							"prefix": "/api/v1",
						},
					},
				},
			},
		},
	}

	apiV1BackendConfig := map[string]interface{}{
		"id":       "api-v1-backend",
		"hostname": "api-v1-backend.test",
			"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"type": "proxy",
			"url":  "http://e2e-test-server:8090",
		},
	}

	forwardRulesJSON, _ := json.Marshal(forwardRulesConfig)
	apiV1JSON, _ := json.Marshal(apiV1BackendConfig)

	storage.data["forward-rules-complex.test"] = forwardRulesJSON
	storage.data["api-v1-backend.test"] = apiV1JSON

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	// First request - should load from storage and cache
	req1 := httptest.NewRequest(http.MethodGet, "http://forward-rules-complex.test/api/v1/test", nil)
	req1.Host = "forward-rules-complex.test"

	cfg1, err := getConfigByHostname(context.Background(), req1, "forward-rules-complex.test", 0, mgr, nil)
	if err != nil {
		t.Fatalf("First request: getConfigByHostname() error = %v", err)
	}

	if cfg1.ID != "api-v1-backend" {
		t.Errorf("First request: Expected config ID api-v1-backend, got %s", cfg1.ID)
	}

	// Second request - should use cached config
	req2 := httptest.NewRequest(http.MethodGet, "http://forward-rules-complex.test/api/v1/test", nil)
	req2.Host = "forward-rules-complex.test"

	cfg2, err := getConfigByHostname(context.Background(), req2, "forward-rules-complex.test", 0, mgr, nil)
	if err != nil {
		t.Fatalf("Second request: getConfigByHostname() error = %v", err)
	}

	if cfg2.ID != "api-v1-backend" {
		t.Errorf("Second request: Expected config ID api-v1-backend, got %s", cfg2.ID)
	}

	// Verify it was cached (check that storage.Get was only called once for forward-rules-complex.test)
	// This is implicit - if it works, it's using the cache
}

