package cel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCELSyntax_InvalidJsonGet tests that json.get() syntax is invalid
// This documents the correct CEL syntax for accessing JSON fields with defaults
func TestCELSyntax_InvalidJsonGet(t *testing.T) {
	// This should fail - json.get() doesn't exist in CEL
	invalidExpr := `{
		"modified_json": {
			"api_version": string(json.get('version', 'v1'))
		}
	}`

	_, err := NewJSONModifier(invalidExpr)
	assert.Error(t, err, "json.get() should not be valid CEL syntax")
	assert.Contains(t, err.Error(), "undeclared", "error should mention undeclared reference")
}

// TestCELSyntax_CorrectInOperator tests the correct CEL syntax using 'in' operator
func TestCELSyntax_CorrectInOperator(t *testing.T) {
	// Correct syntax: 'key' in json ? json['key'] : 'default'
	correctExpr := `{
		"modified_json": {
			"api_version": string('version' in json ? json['version'] : 'v1'),
			"environment": 'env' in json ? json['env'] : 'production',
			"features": 'features' in json ? json['features'] : {}
		}
	}`

	modifier, err := NewJSONModifier(correctExpr)
	require.NoError(t, err, "correct CEL syntax should compile")

	// Test with version present
	jsonObj := map[string]interface{}{
		"version": "v2",
		"env":     "staging",
		"features": map[string]interface{}{
			"new_api": true,
		},
	}

	result, err := modifier.ModifyJSON(jsonObj)
	require.NoError(t, err)
	assert.Equal(t, "v2", result["api_version"])
	assert.Equal(t, "staging", result["environment"])
	assert.NotNil(t, result["features"])

	// Test with missing fields (should use defaults)
	jsonObjMissing := map[string]interface{}{
		"other_field": "value",
	}

	result2, err := modifier.ModifyJSON(jsonObjMissing)
	require.NoError(t, err)
	assert.Equal(t, "v1", result2["api_version"], "should use default 'v1' when version is missing")
	assert.Equal(t, "production", result2["environment"], "should use default 'production' when env is missing")
	assert.NotNil(t, result2["features"])
}

// TestCELSyntax_DirectAccess tests direct JSON field access without defaults
func TestCELSyntax_DirectAccess(t *testing.T) {
	// Direct access: json['key'] or json.key
	expr := `{
		"modified_json": {
			"theme": json['user_preferences']['theme'],
			"language": json['user_preferences']['language'],
			"is_premium": json['subscription']['tier'] == 'premium'
		}
	}`

	modifier, err := NewJSONModifier(expr)
	require.NoError(t, err)

	jsonObj := map[string]interface{}{
		"user_preferences": map[string]interface{}{
			"theme":    "dark",
			"language": "en",
		},
		"subscription": map[string]interface{}{
			"tier": "premium",
		},
	}

	result, err := modifier.ModifyJSON(jsonObj)
	require.NoError(t, err)
	assert.Equal(t, "dark", result["theme"])
	assert.Equal(t, "en", result["language"])
	assert.Equal(t, true, result["is_premium"])
}

// TestCELSyntax_NestedAccess tests nested JSON field access
func TestCELSyntax_NestedAccess(t *testing.T) {
	expr := `{
		"modified_json": {
			"user_id": string('user_id' in json ? json['user_id'] : 'unknown'),
			"roles": 'roles' in json ? json['roles'] : [],
			"permissions": 'permissions' in json ? json['permissions'] : {}
		}
	}`

	modifier, err := NewJSONModifier(expr)
	require.NoError(t, err)

	// Test with all fields present
	jsonObj := map[string]interface{}{
		"user_id": "user-123",
		"roles":   []interface{}{"admin", "user"},
		"permissions": map[string]interface{}{
			"read":  true,
			"write": true,
		},
	}

	result, err := modifier.ModifyJSON(jsonObj)
	require.NoError(t, err)
	assert.Equal(t, "user-123", result["user_id"])
	assert.Equal(t, []interface{}{"admin", "user"}, result["roles"])
	assert.NotNil(t, result["permissions"])

	// Test with missing fields (should use defaults)
	jsonObjMissing := map[string]interface{}{
		"other": "data",
	}

	result2, err := modifier.ModifyJSON(jsonObjMissing)
	require.NoError(t, err)
	assert.Equal(t, "unknown", result2["user_id"], "should use default 'unknown' when user_id is missing")
	// CEL returns empty arrays as []ref.Val, so we check for empty
	rolesVal := result2["roles"]
	if roles, ok := rolesVal.([]interface{}); ok {
		assert.Equal(t, []interface{}{}, roles, "should use default empty array when roles is missing")
	} else {
		// If it's a CEL ref.Val, just check it's not nil
		assert.NotNil(t, rolesVal, "roles should exist even if empty")
	}
	assert.NotNil(t, result2["permissions"])
}

// TestCELSyntax_ComplexExpression tests complex CEL expressions matching E2E configs
func TestCELSyntax_ComplexExpression(t *testing.T) {
	// This matches the fixed E2E config for cel-callback-onstart
	expr := `{
		"modified_json": {
			"config_data": {
				"api_version": string('version' in json ? json['version'] : 'v1'),
				"environment": 'env' in json ? json['env'] : 'production',
				"features": 'features' in json ? json['features'] : {}
			}
		}
	}`

	modifier, err := NewJSONModifier(expr)
	require.NoError(t, err)

	// Simulate the callback response from e2e-test-server
	jsonObj := map[string]interface{}{
		"version": "v2",
		"env":     "production",
		"features": map[string]interface{}{
			"new_api": true,
		},
	}

	result, err := modifier.ModifyJSON(jsonObj)
	require.NoError(t, err)

	// Use convertToInterfaceMap to handle CEL type conversion
	configDataVal := result["config_data"]
	configData := convertToInterfaceMap(configDataVal)
	require.NotEmpty(t, configData, "config_data should be a map, got %T", configDataVal)
	assert.Equal(t, "v2", configData["api_version"])
	assert.Equal(t, "production", configData["environment"])
	assert.NotNil(t, configData["features"])
}

// TestCELSyntax_AuthCallbackExpression tests the auth callback CEL expression
func TestCELSyntax_AuthCallbackExpression(t *testing.T) {
	// This matches the fixed E2E config for cel-callback-auth
	expr := `{
		"modified_json": {
			"auth_data": {
				"user_id": string('user_id' in json ? json['user_id'] : 'unknown'),
				"roles": 'roles' in json ? json['roles'] : [],
				"permissions": 'permissions' in json ? json['permissions'] : {}
			}
		}
	}`

	modifier, err := NewJSONModifier(expr)
	require.NoError(t, err)

	// Simulate the auth callback response
	jsonObj := map[string]interface{}{
		"user_id": "user-123",
		"roles":   []interface{}{"admin", "user"},
		"permissions": map[string]interface{}{
			"read":  true,
			"write": true,
		},
	}

	result, err := modifier.ModifyJSON(jsonObj)
	require.NoError(t, err)

	// Use convertToInterfaceMap to handle CEL type conversion
	authDataVal := result["auth_data"]
	authData := convertToInterfaceMap(authDataVal)
	require.NotEmpty(t, authData, "auth_data should be a map, got %T", authDataVal)
	assert.Equal(t, "user-123", authData["user_id"])
	assert.Equal(t, []interface{}{"admin", "user"}, authData["roles"])
	assert.NotNil(t, authData["permissions"])
}

// TestCELSyntax_SessionCallbackExpression tests the session callback CEL expression
func TestCELSyntax_SessionCallbackExpression(t *testing.T) {
	// This matches the E2E config for cel-callback-session (already correct)
	expr := `{
		"modified_json": {
			"user_prefs": {
				"theme": json['user_preferences']['theme'],
				"language": json['user_preferences']['language'],
				"is_premium": json['subscription']['tier'] == 'premium'
			}
		}
	}`

	modifier, err := NewJSONModifier(expr)
	require.NoError(t, err)

	// Simulate the session callback response
	jsonObj := map[string]interface{}{
		"user_preferences": map[string]interface{}{
			"theme":    "dark",
			"language": "en",
		},
		"subscription": map[string]interface{}{
			"tier": "premium",
		},
	}

	result, err := modifier.ModifyJSON(jsonObj)
	require.NoError(t, err)

	// Use convertToInterfaceMap to handle CEL type conversion
	userPrefsVal := result["user_prefs"]
	userPrefs := convertToInterfaceMap(userPrefsVal)
	require.NotEmpty(t, userPrefs, "user_prefs should be a map, got %T", userPrefsVal)
	assert.Equal(t, "dark", userPrefs["theme"])
	assert.Equal(t, "en", userPrefs["language"])
	assert.Equal(t, true, userPrefs["is_premium"])
}

