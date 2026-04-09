package configloader

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

func TestEmbeddedForwardRule_JSONYAMLParentParity(t *testing.T) {
	resetCache()

	tests := []struct {
		name       string
		configData []byte
	}{
		{
			name: "json config",
			configData: mustJSON(t, map[string]any{
				"id":           "gateway",
				"hostname":     "gateway.test",
				"workspace_id": "test-workspace",
				"action": map[string]any{
					"type": "proxy",
					"url":  "http://upstream.internal",
				},
				"forward_rules": []map[string]any{
					{
						"origin": map[string]any{
							"id":           "inline-backend",
							"hostname":     "inline-backend.internal",
							"workspace_id": "test-workspace",
							"action": map[string]any{
								"type": "proxy",
								"url":  "http://inline-backend.internal",
							},
						},
						"rules": []map[string]any{
							{"path": map[string]any{"prefix": "/api"}},
						},
					},
				},
			}),
		},
		{
			name: "yaml config",
			configData: []byte(`
id: gateway
hostname: gateway.test
workspace_id: test-workspace
action:
  type: proxy
  url: http://upstream.internal
forward_rules:
  - origin:
      id: inline-backend
      hostname: inline-backend.internal
      workspace_id: test-workspace
      action:
        type: proxy
        url: http://inline-backend.internal
    rules:
      - path:
          prefix: /api
`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCache()

			st := &mockStorage{data: map[string][]byte{
				"gateway.test": tt.configData,
			}}
			mgr := &mockManager{
				storage: st,
				settings: manager.GlobalSettings{
					OriginLoaderSettings: manager.OriginLoaderSettings{
						MaxOriginRecursionDepth: 10,
					},
				},
			}

			req := httptest.NewRequest(http.MethodGet, "http://gateway.test/api/users", nil)
			req.Host = "gateway.test"

			cfg, err := getConfigByHostname(context.Background(), req, "gateway.test", 0, mgr, nil)
			if err != nil {
				t.Fatalf("getConfigByHostname() error = %v", err)
			}

			if cfg.ID != "inline-backend" {
				t.Fatalf("expected inline backend config, got %q", cfg.ID)
			}
			if cfg.Parent == nil {
				t.Fatal("expected parent to be set on embedded config")
			}
			if cfg.Parent.ID != "gateway" {
				t.Fatalf("expected parent ID %q, got %q", "gateway", cfg.Parent.ID)
			}
			if cfg.Parent.Hostname != "gateway.test" {
				t.Fatalf("expected parent hostname %q, got %q", "gateway.test", cfg.Parent.Hostname)
			}
		})
	}
}

func TestEmbeddedFallbackOrigin_RespectsGlobalRecursionDepth(t *testing.T) {
	resetCache()

	cfgBytes := mustJSON(t, map[string]any{
		"id":           "primary",
		"hostname":     "primary.test",
		"workspace_id": "test-workspace",
		"action": map[string]any{
			"type": "proxy",
			"url":  "http://primary.internal",
		},
		"fallback_origin": map[string]any{
			"on_error": true,
			// max_depth is intentionally high. Global recursion depth must win.
			"max_depth": 999,
			"origin": map[string]any{
				"id":           "inline-fallback",
				"hostname":     "inline-fallback.internal",
				"workspace_id": "test-workspace",
				"action": map[string]any{
					"type": "proxy",
					"url":  "http://fallback.internal",
				},
			},
		},
	})

	st := &mockStorage{data: map[string][]byte{
		"primary.test": cfgBytes,
	}}
	mgr := &mockManager{
		storage: st,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginRecursionDepth: 1,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://primary.test/api", nil)
	req.Host = "primary.test"

	cfg, err := getConfigByHostname(context.Background(), req, "primary.test", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}
	if cfg.FallbackLoader == nil {
		t.Fatal("expected fallback loader to be configured")
	}

	// First fallback load from depth=0 should succeed.
	fallbackCfg, err := cfg.FallbackLoader(context.Background(), req, cfg.FallbackOrigin)
	if err != nil {
		t.Fatalf("FallbackLoader() first call error = %v", err)
	}
	if fallbackCfg.ID != "inline-fallback" {
		t.Fatalf("expected fallback ID %q, got %q", "inline-fallback", fallbackCfg.ID)
	}
	if fallbackCfg.Parent == nil || fallbackCfg.Parent.ID != "primary" {
		t.Fatalf("expected fallback parent ID %q, got %#v", "primary", fallbackCfg.Parent)
	}

	// Starting at max depth should fail regardless of fallback_origin.max_depth.
	deepCtx := WithFallbackDepth(context.Background(), 1)
	_, err = cfg.FallbackLoader(deepCtx, req, cfg.FallbackOrigin)
	if !errors.Is(err, ErrMaxFallbackDepthReached) {
		t.Fatalf("expected ErrMaxFallbackDepthReached, got %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return b
}
