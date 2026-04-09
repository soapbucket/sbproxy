package config_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnLoadBasic(t *testing.T) {
	// Create mock server that receives POST data with origin_id and hostname
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a POST request
		assert.Equal(t, "POST", r.Method)

		// Decode POST data
		var data map[string]any
		err := json.NewDecoder(r.Body).Decode(&data)
		require.NoError(t, err)

		// Verify POST data contains origin_id and hostname
		assert.Equal(t, "test-origin-123", data["origin_id"])
		assert.Equal(t, "api.example.com", data["hostname"])

		// Return params
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"environment":     "prod",
			"feature_enabled": true,
			"rate_limit":      10000,
			"backends": map[string]string{
				"primary":  "https://api-prod.backend.com",
				"fallback": "https://api-prod-fallback.backend.com",
			},
		})
	}))
	defer server.Close()

	// Create config JSON with OnLoad callback
	configJSON := fmt.Sprintf(`{
		"id": "test-origin-123",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "%s",
			"method": "POST",
			"timeout": 10,
			"expected_status_codes": [200]
		}]
	}`, server.URL)

	// Load config
	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify params were loaded
	require.NotNil(t, cfg.Params)
	assert.Equal(t, "prod", cfg.Params["environment"])
	assert.Equal(t, true, cfg.Params["feature_enabled"])
	assert.Equal(t, float64(10000), cfg.Params["rate_limit"])

	// Verify nested map
	backends, ok := cfg.Params["backends"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "https://api-prod.backend.com", backends["primary"])
	assert.Equal(t, "https://api-prod-fallback.backend.com", backends["fallback"])
}

func TestOnLoadWithCacheDuration(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"environment": "prod",
			"call_number": callCount,
		})
	}))
	defer server.Close()

	configJSON := fmt.Sprintf(`{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "%s",
			"timeout": 10,
			"cache_duration": "5m"
		}]
	}`, server.URL)

	// Load config - should call server
	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)
	assert.Equal(t, "prod", cfg.Params["environment"])
}

func TestOnLoadWithCELProcessing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"env": "production",
			"limits": map[string]any{
				"rpm":   10000,
				"burst": 1000,
			},
			"backends": map[string]any{
				"primary":  "https://api-prod.backend.com",
				"fallback": "https://api-prod-fallback.backend.com",
			},
		})
	}))
	defer server.Close()

	// Use CEL to transform the response
	configJSON := fmt.Sprintf(`{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "%s",
			"timeout": 10,
			"cel_expr": "{\"modified_json\": {\"environment\": json.env, \"rate_limit\": json.limits.rpm, \"backend\": json.backends.primary}}"
		}]
	}`, server.URL)

	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)

	// Verify CEL transformed the response
	assert.Equal(t, "production", cfg.Params["environment"])
	assert.Equal(t, float64(10000), cfg.Params["rate_limit"])
	assert.Equal(t, "https://api-prod.backend.com", cfg.Params["backend"])

	// Original fields should not be present
	assert.Nil(t, cfg.Params["env"])
	assert.Nil(t, cfg.Params["limits"])
}

func TestOnLoadWithLuaProcessing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"environment": "prod",
			"rate_limits": map[string]any{
				"dev":     100,
				"staging": 1000,
				"prod":    10000,
			},
		})
	}))
	defer server.Close()

	// Use Lua to extract the rate limit for the environment
	configJSON := fmt.Sprintf(`{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "%s",
			"timeout": 10,
			"lua_script": "local env = json.environment or 'dev'; local rate = json.rate_limits[env] or 100; return {modified_json = {environment = env, rate_limit = rate, debug = env ~= 'prod'}}"
		}]
	}`, server.URL)

	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)

	// Verify Lua transformed the response
	assert.Equal(t, "prod", cfg.Params["environment"])
	assert.Equal(t, float64(10000), cfg.Params["rate_limit"])
	assert.Equal(t, false, cfg.Params["debug"])
}

func TestOnLoadFailureNonFatal(t *testing.T) {
	// Server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	configJSON := fmt.Sprintf(`{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "%s",
			"timeout": 10
		}]
	}`, server.URL)

	// Config should still load even though callback failed
	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Params should be empty but initialized
	require.NotNil(t, cfg.Params)
	assert.Empty(t, cfg.Params)
}

func TestOnLoadNetworkFailureNonFatal(t *testing.T) {
	// Use invalid URL that will fail to connect
	configJSON := `{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "http://invalid-host-that-does-not-exist-12345.com",
			"timeout": 1
		}]
	}`

	// Config should still load even though callback failed
	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Params should be empty but initialized
	require.NotNil(t, cfg.Params)
	assert.Empty(t, cfg.Params)
}

func TestOnLoadNoCallback(t *testing.T) {
	// Config without OnLoad callback
	configJSON := `{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		}
	}`

	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Params should be empty but initialized
	require.NotNil(t, cfg.Params)
	assert.Empty(t, cfg.Params)
}

func TestOnLoadWithCustomHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom headers
		assert.Equal(t, "Bearer test-token-123", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"environment": "prod",
		})
	}))
	defer server.Close()

	configJSON := fmt.Sprintf(`{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "%s",
			"timeout": 10,
			"headers": {
				"Authorization": ["Bearer test-token-123"],
				"Content-Type": ["application/json"]
			}
		}]
	}`, server.URL)

	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)
	assert.Equal(t, "prod", cfg.Params["environment"])
}

func TestOnLoadWithExpectedStatusCodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted) // 202
		json.NewEncoder(w).Encode(map[string]any{
			"environment": "prod",
		})
	}))
	defer server.Close()

	configJSON := fmt.Sprintf(`{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "%s",
			"timeout": 10,
			"expected_status_codes": [200, 202]
		}]
	}`, server.URL)

	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)
	assert.Equal(t, "prod", cfg.Params["environment"])
}

func TestOnLoadComplexNestedData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"environment": "prod",
			"features": map[string]any{
				"new_api": map[string]any{
					"enabled":   true,
					"version":   "2.0",
					"endpoints": []string{"/api/v2/users", "/api/v2/posts"},
				},
				"beta_ui": map[string]any{
					"enabled": false,
					"rollout": 0.0,
				},
			},
			"rate_limits": []any{
				map[string]any{"path": "/api/users", "limit": 1000},
				map[string]any{"path": "/api/posts", "limit": 5000},
			},
		})
	}))
	defer server.Close()

	configJSON := fmt.Sprintf(`{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "%s",
			"timeout": 10
		}]
	}`, server.URL)

	cfg, err := config.Load([]byte(configJSON))
	require.NoError(t, err)

	// Verify top-level
	assert.Equal(t, "prod", cfg.Params["environment"])

	// Verify nested maps
	features, ok := cfg.Params["features"].(map[string]any)
	require.True(t, ok)

	newAPI, ok := features["new_api"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, newAPI["enabled"])
	assert.Equal(t, "2.0", newAPI["version"])

	// Verify arrays
	endpoints, ok := newAPI["endpoints"].([]any)
	require.True(t, ok)
	assert.Len(t, endpoints, 2)
	assert.Equal(t, "/api/v2/users", endpoints[0])

	rateLimits, ok := cfg.Params["rate_limits"].([]any)
	require.True(t, ok)
	assert.Len(t, rateLimits, 2)
}

func TestLoadWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"environment": "test",
		})
	}))
	defer server.Close()

	configJSON := fmt.Sprintf(`{
		"id": "test-origin",
		"hostname": "api.example.com",
		"workspace_id": "test-workspace",
		"action": {
			"type": "proxy",
			"url": "http://example.com"
		},
		"on_load": [{
			"url": "%s",
			"timeout": 10
		}]
	}`, server.URL)

	// Test LoadWithContext with a context
	ctx := context.Background()
	cfg, err := config.LoadWithContext(ctx, []byte(configJSON))
	require.NoError(t, err)
	assert.Equal(t, "test", cfg.Params["environment"])
}
