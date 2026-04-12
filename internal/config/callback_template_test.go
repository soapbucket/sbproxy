package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/middleware/modifier"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCallbackTemplateVariables_ConfigData(t *testing.T) {
	// Test that template variables like {{origin.params.config_data.api_version}} resolve correctly
	// This simulates the on_load callback scenario

	// Create a config with on_load callback data
	cfg := &Config{
		ID:       "test-origin",
		Hostname: "test.example.com",
		Params: map[string]any{
			"config_data": map[string]any{
				"api_version": "v2",
				"environment": "production",
			},
		},
	}

	// Create request with config in context
	req := httptest.NewRequest("GET", "/", nil)
	ctx := req.Context()

	// Create RequestData with config data (as done in configloader.Load)
	requestData := reqctx.NewRequestData()
	requestData.OriginCtx = &reqctx.OriginContext{Params: cfg.Params}
	ctx = reqctx.SetRequestData(ctx, requestData)

	req = req.WithContext(ctx)

	// Test resolving config variables using the modifier's resolveTemplateVariables
	// We'll test this by creating a request modifier and checking header resolution
	modifierJSON := `{
		"headers": {
			"set": {
				"X-API-Version": "{{origin.params.config_data.api_version}}",
				"X-Environment": "{{origin.params.config_data.environment}}"
			}
		}
	}`

	var rm modifier.RequestModifier
	err := json.Unmarshal([]byte(modifierJSON), &rm)
	require.NoError(t, err)

	// Apply the modifier
	err = rm.Apply(req)
	require.NoError(t, err)

	// Verify headers were set correctly
	assert.Equal(t, "v2", req.Header.Get("X-API-Version"))
	assert.Equal(t, "production", req.Header.Get("X-Environment"))
}

func TestCallbackTemplateVariables_RequestData(t *testing.T) {
	// Test that template variables like {{request.data.user_prefs.theme}} resolve correctly
	// This simulates the session/auth callback scenario

	// Create request with request_data in context
	req := httptest.NewRequest("GET", "/", nil)
	ctx := req.Context()

	// Create RequestData with callback data (from session/auth callbacks)
	requestData := reqctx.NewRequestData()
	requestData.Data = map[string]any{
		"user_prefs": map[string]any{
			"theme":    "dark",
			"language": "en",
		},
		"auth_data": map[string]any{
			"user_id": "user123",
			"roles":   []any{"admin", "user"},
		},
	}
	ctx = reqctx.SetRequestData(ctx, requestData)
	req = req.WithContext(ctx)

	// Test resolving request_data variables via request.data namespace
	modifierJSON := `{
		"headers": {
			"set": {
				"X-User-Theme": "{{request.data.user_prefs.theme}}",
				"X-User-Language": "{{request.data.user_prefs.language}}",
				"X-User-ID": "{{request.data.auth_data.user_id}}"
			}
		}
	}`

	var rm modifier.RequestModifier
	err := json.Unmarshal([]byte(modifierJSON), &rm)
	require.NoError(t, err)

	// Apply the modifier
	err = rm.Apply(req)
	require.NoError(t, err)

	// Verify headers were set correctly
	assert.Equal(t, "dark", req.Header.Get("X-User-Theme"))
	assert.Equal(t, "en", req.Header.Get("X-User-Language"))
	assert.Equal(t, "user123", req.Header.Get("X-User-ID"))
}

// TestCallbackOnLoad_Integration verifies CEL expression processing in on_load callbacks.
// The CEL modifier extracts the inner map from the "modified_json" key, so Params
// contains the unwrapped config_data directly.
func TestCallbackOnLoad_Integration(t *testing.T) {
	// Create mock server for on_load callback
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"version": "v2",
			"env":     "production",
			"features": map[string]any{
				"new_api": true,
			},
		})
	}))
	defer server.Close()

	// Create config with on_load callback
	// CEL expression uses modified_json to replace the result with a restructured map.
	configJSON := `{
		"id": "cel-callback-onstart",
		"hostname": "cel-callback-onstart.test",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "` + server.URL + `",
			"method": "GET",
			"timeout": 5,
			"cel_expr": "{\"modified_json\": {\"config_data\": {\"api_version\": string(json['version']), \"environment\": json['env'], \"features\": json['features']}}}"
		}],
		"request_modifiers": [
			{
				"headers": {
					"set": {
						"X-API-Version": "{{origin.params.config_data.api_version}}",
						"X-Environment": "{{origin.params.config_data.environment}}"
					}
				}
			}
		]
	}`

	cfg, err := Load([]byte(configJSON))
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Params)

	// The CEL modifier extracts the modified_json inner map, so Params
	// directly contains {"config_data": {...}} (not wrapped in modified_json).
	configData, ok := cfg.Params["config_data"].(map[string]any)
	require.True(t, ok, "config_data should be directly in Params")
	assert.Equal(t, "v2", configData["api_version"])
	assert.Equal(t, "production", configData["environment"])

	// Create request and simulate the flow
	req := httptest.NewRequest("GET", "/", nil)
	ctx := req.Context()

	// Simulate what configloader.Load does - populate RequestData with origin params
	requestData := reqctx.NewRequestData()
	requestData.OriginCtx = &reqctx.OriginContext{Params: cfg.Params}
	ctx = reqctx.SetRequestData(ctx, requestData)
	req = req.WithContext(ctx)

	// Apply request modifiers (this is where template variables should be resolved)
	err = cfg.RequestModifiers.Apply(req)
	require.NoError(t, err)

	// Verify headers were set correctly
	assert.Equal(t, "v2", req.Header.Get("X-API-Version"))
	assert.Equal(t, "production", req.Header.Get("X-Environment"))
}
