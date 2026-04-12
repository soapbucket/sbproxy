package modifier

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNestedTemplateVariables_RuleCallback tests deeply nested template variable resolution
// This matches the E2E config for rule callback tests where we need to access
// request_data.user_data.subscription.tier
func TestNestedTemplateVariables_RuleCallback(t *testing.T) {
	// Simulate the session callback data structure from e2e-test-server
	// The callback returns data that gets stored under variable_name "user_data"
	// This data lives in SessionData.Data, not RequestData.Data
	req := httptest.NewRequest("GET", "/", nil)
	requestData := reqctx.NewRequestData()
	requestData.SessionData = &reqctx.SessionData{
		Data: map[string]any{
			"user_data": map[string]any{
				"subscription": map[string]any{
					"tier": "premium",
				},
				"feature_flags": map[string]any{
					"beta": true,
				},
			},
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	// Test resolving deeply nested path using RequestModifier (which calls resolveTemplateVariables internally)
	// Session callback data should be accessed via session_data, not request_data
	modifierJSON := `{
		"headers": {
			"set": {
				"X-User-Tier": "{{session.data.user_data.subscription.tier}}",
				"X-Feature-Beta": "{{session.data.user_data.feature_flags.beta}}"
			}
		}
	}`

	var rm RequestModifier
	err := json.Unmarshal([]byte(modifierJSON), &rm)
	require.NoError(t, err)

	err = rm.Apply(req)
	require.NoError(t, err)

	assert.Equal(t, "premium", req.Header.Get("X-User-Tier"), "should resolve deeply nested path")
	// Boolean values are converted to string by Mustache (may be "True"/"False" or "true"/"false")
	featureBeta := req.Header.Get("X-Feature-Beta")
	assert.NotEmpty(t, featureBeta, "X-Feature-Beta should be set")
	assert.Contains(t, []string{"true", "false", "True", "False"}, featureBeta, "should be boolean string")
}

// TestNestedTemplateVariables_ConfigData tests nested config data access
func TestNestedTemplateVariables_ConfigData(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	requestData := reqctx.NewRequestData()
	requestData.OriginCtx = &reqctx.OriginContext{
		Params: map[string]any{
			"config_data": map[string]any{
				"api_version": "v2",
				"environment": "production",
			},
			"app_config": map[string]any{
				"version": "1.0.0",
				"features": map[string]any{
					"new_api": true,
				},
			},
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	// Test using RequestModifier
	modifierJSON := `{
		"headers": {
			"set": {
				"X-API-Version": "{{origin.params.config_data.api_version}}",
				"X-Feature-New-API": "{{origin.params.app_config.features.new_api}}"
			}
		}
	}`

	var rm RequestModifier
	err := json.Unmarshal([]byte(modifierJSON), &rm)
	require.NoError(t, err)

	err = rm.Apply(req)
	require.NoError(t, err)

	assert.Equal(t, "v2", req.Header.Get("X-API-Version"), "should resolve nested config path")
	// Mustache converts boolean true to "True" (capitalized)
	featureValue := req.Header.Get("X-Feature-New-API")
	assert.Contains(t, []string{"true", "True"}, featureValue, "should resolve deeply nested config path (Mustache may capitalize boolean)")
}

// TestNestedTemplateVariables_MissingPath tests that missing nested paths return empty string
func TestNestedTemplateVariables_MissingPath(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	requestData := reqctx.NewRequestData()
	requestData.Data = map[string]any{
		"user_data": map[string]any{
			"subscription": map[string]any{
				"tier": "premium",
			},
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	// Test using RequestModifier
	modifierJSON := `{
		"headers": {
			"set": {
				"X-Missing-Intermediate": "{{request.data.user_data.missing.tier}}",
				"X-Missing-Final": "{{request.data.user_data.subscription.missing}}"
			}
		}
	}`

	var rm RequestModifier
	err := json.Unmarshal([]byte(modifierJSON), &rm)
	require.NoError(t, err)

	err = rm.Apply(req)
	require.NoError(t, err)

	assert.Equal(t, "", req.Header.Get("X-Missing-Intermediate"), "should return empty string for missing path")
	assert.Equal(t, "", req.Header.Get("X-Missing-Final"), "should return empty string for missing final path")
}

// TestNestedTemplateVariables_RequestModifierIntegration tests nested variables in actual request modifiers
// This matches the exact E2E config structure for rule callback tests
func TestNestedTemplateVariables_RequestModifierIntegration(t *testing.T) {
	// Load a modifier config matching the E2E rule callback test
	// Session callback data should be accessed via session_data, not request_data
	modifierJSON := `{
		"headers": {
			"set": {
				"X-User-Tier": "{{session.data.user_data.subscription.tier}}",
				"X-Feature-Flags": "{{session.data.user_data.feature_flags}}"
			}
		}
	}`

	var rm RequestModifier
	err := json.Unmarshal([]byte(modifierJSON), &rm)
	require.NoError(t, err)

	// Create request with nested callback data in SessionData.Data (from session callbacks)
	req := httptest.NewRequest("GET", "/", nil)
	requestData := reqctx.NewRequestData()
	requestData.SessionData = &reqctx.SessionData{
		Data: map[string]any{
			"user_data": map[string]any{
				"subscription": map[string]any{
					"tier": "premium",
				},
				"feature_flags": map[string]any{
					"beta": true,
				},
			},
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	// Apply the modifier
	err = rm.Apply(req)
	require.NoError(t, err)

	// Verify headers were set correctly
	assert.Equal(t, "premium", req.Header.Get("X-User-Tier"), "X-User-Tier should be set from nested path")
	// Note: feature_flags is a map, so it will be converted to string representation
	featureFlags := req.Header.Get("X-Feature-Flags")
	assert.NotEmpty(t, featureFlags, "X-Feature-Flags should be set")
}

// TestNestedTemplateVariables_NonMapIntermediate tests that non-map intermediate values return empty
func TestNestedTemplateVariables_NonMapIntermediate(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	requestData := reqctx.NewRequestData()
	requestData.Data = map[string]any{
		"user_data": "not-a-map", // This is a string, not a map
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	// Test using RequestModifier
	modifierJSON := `{
		"headers": {
			"set": {
				"X-User-Tier": "{{request.data.user_data.subscription.tier}}"
			}
		}
	}`

	var rm RequestModifier
	err := json.Unmarshal([]byte(modifierJSON), &rm)
	require.NoError(t, err)

	err = rm.Apply(req)
	require.NoError(t, err)

	// When Mustache can't access a field on a non-map, it returns an error
	// The template resolver returns the original template on error for debugging
	// In practice, this means the header will contain the unresolved template
	headerValue := req.Header.Get("X-User-Tier")
	// Either empty string (if Mustache handles it gracefully) or the original template (if error)
	assert.True(t, headerValue == "" || headerValue == "{{request.data.user_data.subscription.tier}}",
		"should return empty string or original template when intermediate value is not a map, got: %s", headerValue)
}
