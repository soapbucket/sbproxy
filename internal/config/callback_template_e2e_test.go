package config

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/middleware/modifier"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCallbackTemplateVariables_E2EConfig tests template variable resolution
// with the actual E2E test configurations to identify why they're not working
func TestCallbackTemplateVariables_E2EConfig_OnLoad(t *testing.T) {
	// Load the actual E2E test config
	configJSON := `{
		"lua-callback-onstart.test": {
			"id": "lua-callback-onstart",
			"hostname": "lua-callback-onstart.test",
			"workspace_id": "test-workspace",
			"on_load": [{
				"type": "http",
				"url": "http://e2e-test-server:8090/callback/config",
				"method": "GET",
				"timeout": 5,
				"lua_script": "local result = {}\nresult.api_version = tostring(json['version'] or 'v1')\nresult.environment = json['env'] or 'production'\nresult.features = json['features'] or {}\nreturn result"
			}],
			"action": {
				"type": "proxy",
				"url": "http://e2e-test-server:8090"
			},
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"X-API-Version": "{{origin.params.api_version}}",
							"X-Environment": "{{origin.params.environment}}"
						}
					}
				}
			]
		}
	}`

	// Parse the config
	var configMap map[string]json.RawMessage
	err := json.Unmarshal([]byte(configJSON), &configMap)
	require.NoError(t, err)

	hostnameConfig, ok := configMap["lua-callback-onstart.test"]
	require.True(t, ok, "config should contain hostname")

	// Load the config
	cfg, err := Load(hostnameConfig)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Simulate on_load callback execution
	// The callback would normally execute and populate cfg.Params
	// For this test, we'll manually set Params to simulate the callback result
	cfg.Params = map[string]any{
		"api_version": "v2",
		"environment": "production",
		"features":    map[string]any{},
	}

	// Create request with config in context
	req := httptest.NewRequest("GET", "/", nil)
	ctx := req.Context()

	// Simulate what configloader.Load does - populate OriginCtx.Params
	requestData := reqctx.NewRequestData()
	requestData.OriginCtx = &reqctx.OriginContext{Params: cfg.Params}
	ctx = reqctx.SetRequestData(ctx, requestData)
	req = req.WithContext(ctx)

	// Apply request modifiers (this is where template variables should be resolved)
	err = cfg.RequestModifiers.Apply(req)
	require.NoError(t, err)

	// Verify headers were set correctly
	apiVersion := req.Header.Get("X-API-Version")
	environment := req.Header.Get("X-Environment")

	t.Logf("X-API-Version header value: %q", apiVersion)
	t.Logf("X-Environment header value: %q", environment)

	// Check if template variables were resolved
	if apiVersion == "{{origin.params.api_version}}" {
		t.Error("Template variable {{origin.params.api_version}} was not resolved - still contains literal string")
	}
	if environment == "{{origin.params.environment}}" {
		t.Error("Template variable {{origin.params.environment}} was not resolved - still contains literal string")
	}

	// Verify actual values
	assert.Equal(t, "v2", apiVersion, "X-API-Version should be resolved to 'v2'")
	assert.Equal(t, "production", environment, "X-Environment should be resolved to 'production'")
}

func TestCallbackTemplateVariables_E2EConfig_Session(t *testing.T) {
	// Load the actual E2E test config
	configJSON := `{
		"lua-callback-session.test": {
			"id": "lua-callback-session",
			"hostname": "lua-callback-session.test",
			"workspace_id": "test-workspace",
			"session_config": {
				"enabled": true,
				"cookie_name": "_sb.session",
				"cookie_max_age": 3600,
				"callbacks": [
					{
						"type": "http",
						"url": "http://e2e-test-server:8090/callback/session",
						"method": "POST",
						"variable_name": "user_prefs",
						"timeout": 5,
						"lua_script": "local result = {}\nresult.theme = json['user_preferences']['theme']\nresult.language = json['user_preferences']['language']\nresult.is_premium = json['subscription']['tier'] == 'premium'\nreturn result"
					}
				]
			},
			"action": {
				"type": "proxy",
				"url": "http://e2e-test-server:8090"
			},
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"X-User-Theme": "{{session.data.user_prefs.theme}}",
							"X-User-Language": "{{session.data.user_prefs.language}}"
						}
					}
				}
			]
		}
	}`

	// Parse the config
	var configMap map[string]json.RawMessage
	err := json.Unmarshal([]byte(configJSON), &configMap)
	require.NoError(t, err)

	hostnameConfig, ok := configMap["lua-callback-session.test"]
	require.True(t, ok, "config should contain hostname")

	// Load the config
	cfg, err := Load(hostnameConfig)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Create request with config in context
	req := httptest.NewRequest("GET", "/", nil)
	ctx := req.Context()

	// Simulate session callback execution
	// The callback would normally execute and populate SessionData.Data
	// Note: The callback has variable_name="user_prefs", so the result is wrapped
	requestData := reqctx.NewRequestData()
	requestData.SessionData = &reqctx.SessionData{
		Data: map[string]any{
			"user_prefs": map[string]any{
				"theme":      "dark",
				"language":   "en",
				"is_premium": true,
			},
		},
	}
	ctx = reqctx.SetRequestData(ctx, requestData)
	req = req.WithContext(ctx)

	// Apply request modifiers (this is where template variables should be resolved)
	err = cfg.RequestModifiers.Apply(req)
	require.NoError(t, err)

	// Verify headers were set correctly
	theme := req.Header.Get("X-User-Theme")
	language := req.Header.Get("X-User-Language")

	t.Logf("X-User-Theme header value: %q", theme)
	t.Logf("X-User-Language header value: %q", language)

	// Check if template variables were resolved
	if theme == "{{session.data.user_prefs.theme}}" {
		t.Error("Template variable {{session.data.user_prefs.theme}} was not resolved - still contains literal string")
	}
	if language == "{{session.data.user_prefs.language}}" {
		t.Error("Template variable {{session.data.user_prefs.language}} was not resolved - still contains literal string")
	}

	// Verify actual values
	assert.Equal(t, "dark", theme, "X-User-Theme should be resolved to 'dark'")
	assert.Equal(t, "en", language, "X-User-Language should be resolved to 'en'")
}

func TestCallbackTemplateVariables_E2EConfig_Auth(t *testing.T) {
	// Load the actual E2E test config
	configJSON := `{
		"lua-callback-auth.test": {
			"id": "lua-callback-auth",
			"hostname": "lua-callback-auth.test",
			"workspace_id": "test-workspace",
			"authentication": {
				"type": "api_key",
				"disabled": false,
				"header_name": "X-API-Key",
				"api_keys": ["test-key-123"],
				"authentication_callback": {
					"type": "http",
					"url": "http://e2e-test-server:8090/callback/auth",
					"method": "POST",
					"timeout": 5,
					"lua_script": "local result = {}\nresult.user_id = tostring(json['user_id'] or 'unknown')\nresult.roles = json['roles'] or {}\nresult.permissions = json['permissions'] or {}\nreturn result"
				}
			},
			"action": {
				"type": "proxy",
				"url": "http://e2e-test-server:8090"
			},
			"request_modifiers": [
				{
					"headers": {
						"set": {
							"X-User-ID": "{{request.data.auth_data.user_id}}"
						}
					}
				}
			]
		}
	}`

	// Parse the config
	var configMap map[string]json.RawMessage
	err := json.Unmarshal([]byte(configJSON), &configMap)
	require.NoError(t, err)

	hostnameConfig, ok := configMap["lua-callback-auth.test"]
	require.True(t, ok, "config should contain hostname")

	// Load the config
	cfg, err := Load(hostnameConfig)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Create request with config in context
	req := httptest.NewRequest("GET", "/", nil)
	ctx := req.Context()

	// Simulate auth callback execution
	// The callback would normally execute and populate RequestData.Data["auth_data"]
	// For this test, we'll manually set RequestData.Data to simulate the callback result
	requestData := reqctx.NewRequestData()
	requestData.Data = map[string]any{
		"auth_data": map[string]any{
			"user_id":     "user-123",
			"roles":       []string{"admin", "user"},
			"permissions": map[string]any{},
		},
	}
	ctx = reqctx.SetRequestData(ctx, requestData)
	req = req.WithContext(ctx)

	// Apply request modifiers (this is where template variables should be resolved)
	err = cfg.RequestModifiers.Apply(req)
	require.NoError(t, err)

	// Verify headers were set correctly
	userID := req.Header.Get("X-User-ID")

	t.Logf("X-User-ID header value: %q", userID)

	// Check if template variables were resolved
	if userID == "{{request.data.auth_data.user_id}}" {
		t.Error("Template variable {{request.data.auth_data.user_id}} was not resolved - still contains literal string")
	}

	// Verify actual values
	assert.Equal(t, "user-123", userID, "X-User-ID should be resolved to 'user-123'")
}

// TestCallbackTemplateVariables_ResolverDirectly tests the resolver function directly
// to ensure it works with the expected data structures
func TestCallbackTemplateVariables_ResolverDirectly(t *testing.T) {
	// Test config path resolution
	req := httptest.NewRequest("GET", "/", nil)
	ctx := req.Context()

	requestData := reqctx.NewRequestData()
	requestData.OriginCtx = &reqctx.OriginContext{
		Params: map[string]any{
			"api_version": "v2",
			"environment": "production",
		},
	}
	ctx = reqctx.SetRequestData(ctx, requestData)
	req = req.WithContext(ctx)

	// Test using the modifier's resolveTemplateVariables function
	// We need to access it through the modifier package
	modifierJSON := `{
		"headers": {
			"set": {
				"X-API-Version": "{{origin.params.api_version}}",
				"X-Environment": "{{origin.params.environment}}"
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

	// Test request.data path resolution
	req2 := httptest.NewRequest("GET", "/", nil)
	ctx2 := req2.Context()

	requestData2 := reqctx.NewRequestData()
	requestData2.Data = map[string]any{
		"user_prefs": map[string]any{
			"theme":    "dark",
			"language": "en",
		},
	}
	ctx2 = reqctx.SetRequestData(ctx2, requestData2)
	req2 = req2.WithContext(ctx2)

	modifierJSON2 := `{
		"headers": {
			"set": {
				"X-User-Theme": "{{request.data.user_prefs.theme}}",
				"X-User-Language": "{{request.data.user_prefs.language}}"
			}
		}
	}`

	var rm2 modifier.RequestModifier
	err = json.Unmarshal([]byte(modifierJSON2), &rm2)
	require.NoError(t, err)

	// Apply the modifier
	err = rm2.Apply(req2)
	require.NoError(t, err)

	// Verify headers were set correctly
	assert.Equal(t, "dark", req2.Header.Get("X-User-Theme"))
	assert.Equal(t, "en", req2.Header.Get("X-User-Language"))
}
