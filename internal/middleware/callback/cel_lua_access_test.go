package callback

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/middleware/rule"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestSessionDataAccessInCEL verifies that CEL expressions can access
// session callback data stored in SessionData.Data
func TestSessionDataAccessInCEL(t *testing.T) {
	// Create session data with callback results
	sessionData := &reqctx.SessionData{
		ID: "session-123",
		Data: map[string]any{
			"user_preferences": map[string]any{
				"theme":    "dark",
				"language": "en",
			},
			"feature_flags": map[string]any{
				"beta_features": true,
				"analytics":     false,
			},
			"subscription": map[string]any{
				"tier":   "premium",
				"active": true,
			},
		},
	}

	// Create request with session data
	requestData := &reqctx.RequestData{
		ID:          "req-1",
		SessionData: sessionData,
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	tests := []struct {
		name       string
		celExpr    string
		shouldMatch bool
	}{
		{
			name:        "Access session theme preference",
			celExpr:     `session['data']['user_preferences']['theme'] == "dark"`,
			shouldMatch: true,
		},
		{
			name:        "Access session feature flag",
			celExpr:     `session['data']['feature_flags']['beta_features'] == true`,
			shouldMatch: true,
		},
		{
			name:        "Access session subscription tier",
			celExpr:     `session['data']['subscription']['tier'] == "premium"`,
			shouldMatch: true,
		},
		{
			name:        "Check analytics is disabled",
			celExpr:     `session['data']['feature_flags']['analytics'] == false`,
			shouldMatch: true,
		},
		{
			name:        "Complex condition with AND",
			celExpr:     `session['data']['subscription']['tier'] == "premium" && session['data']['subscription']['active'] == true`,
			shouldMatch: true,
		},
		{
			name:        "Wrong value should not match",
			celExpr:     `session['data']['user_preferences']['theme'] == "light"`,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create rule with CEL expression via JSON (to trigger compilation)
			ruleJSON := fmt.Sprintf(`{"cel_expr": %q}`, tt.celExpr)
			var ruleObj rule.RequestRule
			if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
				t.Fatalf("Failed to compile CEL expression: %v", err)
			}

			// Evaluate
			result := ruleObj.Match(req)
			if result != tt.shouldMatch {
				t.Errorf("CEL evaluation: expected %v, got %v for expr: %s",
					tt.shouldMatch, result, tt.celExpr)
			}
		})
	}
}

// TestAuthDataAccessInCEL verifies that CEL expressions can access
// auth callback data stored in SessionData.AuthData.Data
func TestAuthDataAccessInCEL(t *testing.T) {
	// Create auth data with callback results
	authData := &reqctx.AuthData{
		Type: "oauth",
		Data: map[string]any{
			"email": "admin@example.com",
			"sub":   "user-123",
			// These would be added by auth callback:
			"roles": []any{"admin", "user", "editor"},
			"permissions": map[string]any{
				"read":   true,
				"write":  true,
				"delete": true,
			},
			"metadata": map[string]any{
				"department": "engineering",
				"seniority":  "senior",
			},
		},
	}

	sessionData := &reqctx.SessionData{
		ID:       "session-123",
		AuthData: authData,
	}

	requestData := &reqctx.RequestData{
		ID:          "req-1",
		SessionData: sessionData,
	}

	req := httptest.NewRequest("GET", "/api/admin", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	tests := []struct {
		name        string
		celExpr     string
		shouldMatch bool
	}{
		{
			name:        "Access auth email",
			celExpr:     `session['auth']['email'] == "admin@example.com"`,
			shouldMatch: true,
		},
		{
			name:        "Check admin role",
			celExpr:     `"admin" in session['auth']['roles']`,
			shouldMatch: true,
		},
		{
			name:        "Check write permission",
			celExpr:     `session['auth']['permissions']['write'] == true`,
			shouldMatch: true,
		},
		{
			name:        "Check department",
			celExpr:     `session['auth']['metadata']['department'] == "engineering"`,
			shouldMatch: true,
		},
		{
			name:        "Complex permission check",
			celExpr:     `"admin" in session['auth']['roles'] && session['auth']['permissions']['delete'] == true`,
			shouldMatch: true,
		},
		{
			name:        "Auth type check",
			celExpr:     `session['auth']['type'] == "oauth"`,
			shouldMatch: true,
		},
		{
			name:        "Missing role should not match",
			celExpr:     `"superadmin" in session['auth']['roles']`,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON := fmt.Sprintf(`{"cel_expr": %q}`, tt.celExpr)
			var ruleObj rule.RequestRule
			if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
				t.Fatalf("Failed to compile CEL expression: %v", err)
			}

			result := ruleObj.Match(req)
			if result != tt.shouldMatch {
				t.Errorf("CEL evaluation: expected %v, got %v for expr: %s",
					tt.shouldMatch, result, tt.celExpr)
			}
		})
	}
}

// TestSessionDataAccessInLua verifies that Lua scripts can access
// session callback data stored in SessionData.Data
func TestSessionDataAccessInLua(t *testing.T) {
	// Create session data with callback results
	sessionData := &reqctx.SessionData{
		ID: "session-123",
		Data: map[string]any{
			"user_preferences": map[string]any{
				"theme":    "dark",
				"language": "en",
			},
			"cart": map[string]any{
				"items": []any{
					map[string]any{"id": "1", "price": 10.0},
					map[string]any{"id": "2", "price": 20.0},
				},
				"total": 30.0,
			},
			"subscription": map[string]any{
				"tier":   "premium",
				"active": true,
			},
		},
	}

	requestData := &reqctx.RequestData{
		ID:          "req-1",
		SessionData: sessionData,
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	tests := []struct {
		name        string
		luaScript   string
		shouldMatch bool
	}{
		{
			name: "Access session theme",
			luaScript: `
function match_request(req, ctx)
	return ctx.session.data.user_preferences.theme == "dark"
end
			`,
			shouldMatch: true,
		},
		{
			name: "Access cart total",
			luaScript: `
function match_request(req, ctx)
	return ctx.session.data.cart.total == 30.0
end
			`,
			shouldMatch: true,
		},
		{
			name: "Check subscription tier",
			luaScript: `
function match_request(req, ctx)
	return ctx.session.data.subscription.tier == "premium" and
	       ctx.session.data.subscription.active == true
end
			`,
			shouldMatch: true,
		},
		{
			name: "Calculate cart items",
			luaScript: `
function match_request(req, ctx)
	local items = ctx.session.data.cart.items
	return #items == 2
end
			`,
			shouldMatch: true,
		},
		{
			name: "Complex logic with session data",
			luaScript: `
function match_request(req, ctx)
	local prefs = ctx.session.data.user_preferences
	local sub = ctx.session.data.subscription

	-- Premium users with dark theme
	return sub.tier == "premium" and prefs.theme == "dark"
end
			`,
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON := fmt.Sprintf(`{"lua_script": %q}`, tt.luaScript)
			var ruleObj rule.RequestRule
			if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
				t.Fatalf("Failed to compile Lua script: %v", err)
			}

			result := ruleObj.Match(req)
			if result != tt.shouldMatch {
				t.Errorf("Lua evaluation: expected %v, got %v", tt.shouldMatch, result)
			}
		})
	}
}

// TestAuthDataAccessInLua verifies that Lua scripts can access
// auth callback data stored in SessionData.AuthData.Data
func TestAuthDataAccessInLua(t *testing.T) {
	authData := &reqctx.AuthData{
		Type: "oauth",
		Data: map[string]any{
			"email": "admin@example.com",
			"roles": []any{"admin", "user"},
			"permissions": map[string]any{
				"read":   true,
				"write":  true,
				"delete": false,
			},
		},
	}

	sessionData := &reqctx.SessionData{
		ID:       "session-123",
		AuthData: authData,
	}

	requestData := &reqctx.RequestData{
		ID:          "req-1",
		SessionData: sessionData,
	}

	req := httptest.NewRequest("GET", "/api/admin", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	tests := []struct {
		name        string
		luaScript   string
		shouldMatch bool
	}{
		{
			name: "Check auth type",
			luaScript: `
function match_request(req, ctx)
	return ctx.session.auth.type == "oauth"
end
			`,
			shouldMatch: true,
		},
		{
			name: "Check email domain",
			luaScript: `
function match_request(req, ctx)
	local email = ctx.session.auth.data.email
	return string.find(email, "@example.com") ~= nil
end
			`,
			shouldMatch: true,
		},
		{
			name: "Check for admin role",
			luaScript: `
function match_request(req, ctx)
	local roles = ctx.session.auth.data.roles
	for i, role in ipairs(roles) do
		if role == "admin" then
			return true
		end
	end
	return false
end
			`,
			shouldMatch: true,
		},
		{
			name: "Check write permission",
			luaScript: `
function match_request(req, ctx)
	return ctx.session.auth.data.permissions.write == true
end
			`,
			shouldMatch: true,
		},
		{
			name: "Complex auth check",
			luaScript: `
function match_request(req, ctx)
	local auth = ctx.session.auth.data

	-- Has admin role AND write permission
	local hasAdmin = false
	for i, role in ipairs(auth.roles) do
		if role == "admin" then
			hasAdmin = true
			break
		end
	end

	return hasAdmin and auth.permissions.write == true
end
			`,
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON := fmt.Sprintf(`{"lua_script": %q}`, tt.luaScript)
			var ruleObj rule.RequestRule
			if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
				t.Fatalf("Failed to compile Lua script: %v", err)
			}

			result := ruleObj.Match(req)
			if result != tt.shouldMatch {
				t.Errorf("Lua evaluation: expected %v, got %v", tt.shouldMatch, result)
			}
		})
	}
}

// TestEndToEndSessionCallbackFlow simulates the complete flow:
// 1. Session callback fetches user data
// 2. Data stored in SessionData.Data
// 3. CEL/Lua uses data for request routing
func TestEndToEndSessionCallbackFlow(t *testing.T) {
	// Step 1: Mock callback server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"user_tier":   "premium",
			"api_quota":   10000,
			"rate_limit":  100,
			"features": []string{"analytics", "export", "api_access"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Step 2: Execute session callback
	callback := &Callback{
		URL:    mockServer.URL,
		Method: "GET",
	}

	ctx := context.Background()
	callbackResult, err := callback.Do(ctx, nil)
	if err != nil {
		t.Fatalf("Callback failed: %v", err)
	}

	// Step 3: Store in session (simulating middleware)
	sessionData := &reqctx.SessionData{
		ID:   "session-123",
		Data: callbackResult,
	}

	requestData := &reqctx.RequestData{
		ID:          "req-1",
		SessionData: sessionData,
	}

	req := httptest.NewRequest("GET", "/api/premium-feature", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	// Step 4: Use CEL to make routing decision
	// Note: callback results are wrapped, so access via session['data']['callback'][...]
	tests := []struct {
		name        string
		celExpr     string
		shouldMatch bool
		description string
	}{
		{
			name:        "Premium feature access",
			celExpr:     `session['data']['callback']['user_tier'] == "premium"`,
			shouldMatch: true,
			description: "Premium users can access premium features",
		},
		{
			name:        "API quota check",
			celExpr:     `session['data']['callback']['api_quota'] >= 5000`,
			shouldMatch: true,
			description: "User has sufficient API quota",
		},
		{
			name:        "Rate limit validation",
			celExpr:     `session['data']['callback']['rate_limit'] > 50`,
			shouldMatch: true,
			description: "Rate limit is acceptable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON := fmt.Sprintf(`{"cel_expr": %q}`, tt.celExpr)
			var ruleObj rule.RequestRule
			if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
				t.Fatalf("Failed to compile CEL: %v", err)
			}

			result := ruleObj.Match(req)
			if result != tt.shouldMatch {
				t.Errorf("%s: expected %v, got %v", tt.description, tt.shouldMatch, result)
			}
		})
	}

	t.Log("✅ End-to-end session callback flow validated")
}

// TestEndToEndAuthCallbackFlow simulates the complete auth callback flow
func TestEndToEndAuthCallbackFlow(t *testing.T) {
	// Step 1: Mock auth callback that enriches JWT claims with roles
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]any
		json.NewDecoder(r.Body).Decode(&reqBody)
		
		// Enrich based on email
		response := map[string]any{
			"roles":       []string{"user"},
			"permissions": []string{"read"},
		}
		
		if email, ok := reqBody["email"].(string); ok && email == "admin@example.com" {
			response["roles"] = []string{"admin", "user"}
			response["permissions"] = []string{"read", "write", "delete"}
			response["can_manage_users"] = true
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Step 2: Simulate JWT auth
	initialAuthData := map[string]any{
		"email": "admin@example.com",
		"sub":   "user-123",
		"iss":   "auth.example.com",
	}

	// Step 3: Execute auth callback
	authCallback := &Callback{
		URL:    mockServer.URL,
		Method: "POST",
	}

	ctx := context.Background()
	enrichedData, err := authCallback.Do(ctx, initialAuthData)
	if err != nil {
		t.Fatalf("Auth callback failed: %v", err)
	}

	// Step 4: Merge callback results (simulating auth middleware)
	// Extract wrapped result first
	wrapped, ok := enrichedData["callback"].(map[string]any)
	if !ok {
		t.Fatalf("Expected callback wrapper, got: %v", enrichedData)
	}
	for k, v := range wrapped {
		initialAuthData[k] = v
	}

	authData := &reqctx.AuthData{
		Type: "jwt",
		Data: initialAuthData,
	}

	sessionData := &reqctx.SessionData{
		ID:       "session-123",
		AuthData: authData,
	}

	requestData := &reqctx.RequestData{
		ID:          "req-1",
		SessionData: sessionData,
	}

	req := httptest.NewRequest("DELETE", "/api/users/456", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	// Step 5: Use authorization rules with CEL
	authCheckExpr := `"admin" in session['auth']['roles'] && session['auth']['can_manage_users'] == true`
	
	ruleJSON := fmt.Sprintf(`{"cel_expr": %q}`, authCheckExpr)
	var ruleObj rule.RequestRule
	if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
		t.Fatalf("Failed to compile CEL: %v", err)
	}

	if !ruleObj.Match(req) {
		t.Error("Admin should be authorized to delete users")
	}

	t.Log("✅ End-to-end auth callback flow validated")
}

// TestConfigDataAccessInCEL verifies that CEL expressions can access
// config data from on_load callback stored in RequestData.Config
func TestConfigDataAccessInCEL(t *testing.T) {
	// Simulate on_load callback result stored in OriginCtx.Params
	requestData := &reqctx.RequestData{
		ID: "req-1",
		OriginCtx: &reqctx.OriginContext{
			Params: map[string]any{
				"api_key":        "secret123",
				"feature_enabled": true,
				"max_requests":   1000,
				"environment":    "production",
			},
		},
		Data: map[string]any{},
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	tests := []struct {
		name        string
		celExpr     string
		shouldMatch bool
	}{
		{
			name:        "Access config api_key",
			celExpr:     `origin['params']['api_key'] == "secret123"`,
			shouldMatch: true,
		},
		{
			name:        "Check feature enabled",
			celExpr:     `origin['params']['feature_enabled'] == true`,
			shouldMatch: true,
		},
		{
			name:        "Check max requests",
			celExpr:     `origin['params']['max_requests'] > 100`,
			shouldMatch: true,
		},
		{
			name:        "Check environment",
			celExpr:     `origin['params']['environment'] == "production"`,
			shouldMatch: true,
		},
		{
			name:        "Complex condition",
			celExpr:     `origin['params']['feature_enabled'] == true && origin['params']['max_requests'] > 500`,
			shouldMatch: true,
		},
		{
			name:        "Wrong value should not match",
			celExpr:     `origin['params']['api_key'] == "wrong"`,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON := fmt.Sprintf(`{"cel_expr": %q}`, tt.celExpr)
			var ruleObj rule.RequestRule
			if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
				t.Fatalf("Failed to compile CEL expression: %v", err)
			}

			result := ruleObj.Match(req)
			if result != tt.shouldMatch {
				t.Errorf("CEL evaluation: expected %v, got %v for expr: %s",
					tt.shouldMatch, result, tt.celExpr)
			}
		})
	}
}

// TestConfigDataAccessInLua verifies that Lua scripts can access
// config data from on_load callback stored in OriginCtx.Params
func TestConfigDataAccessInLua(t *testing.T) {
	// Simulate on_load callback result stored in OriginCtx.Params
	requestData := &reqctx.RequestData{
		ID: "req-1",
		OriginCtx: &reqctx.OriginContext{
			Params: map[string]any{
				"api_key":        "secret123",
				"feature_enabled": true,
				"max_requests":   1000,
				"environment":    "production",
			},
		},
		Data: map[string]any{},
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	tests := []struct {
		name        string
		luaScript   string
		shouldMatch bool
	}{
		{
			name: "Access config api_key",
			luaScript: `
function match_request(req, ctx)
	return origin ~= nil and origin.params ~= nil and
	       origin.params.api_key == "secret123"
end
			`,
			shouldMatch: true,
		},
		{
			name: "Check feature enabled",
			luaScript: `
function match_request(req, ctx)
	return origin ~= nil and origin.params ~= nil and
	       origin.params.feature_enabled == true
end
			`,
			shouldMatch: true,
		},
		{
			name: "Check max requests",
			luaScript: `
function match_request(req, ctx)
	return origin ~= nil and origin.params ~= nil and
	       origin.params.max_requests > 100
end
			`,
			shouldMatch: true,
		},
		{
			name: "Check environment",
			luaScript: `
function match_request(req, ctx)
	return origin ~= nil and origin.params ~= nil and
	       origin.params.environment == "production"
end
			`,
			shouldMatch: true,
		},
		{
			name: "Complex condition",
			luaScript: `
function match_request(req, ctx)
	return origin ~= nil and origin.params ~= nil and
	       origin.params.feature_enabled == true and
	       origin.params.max_requests > 500
end
			`,
			shouldMatch: true,
		},
		{
			name: "Access with bracket notation",
			luaScript: `
function match_request(req, ctx)
	return origin ~= nil and origin.params ~= nil and
	       origin.params["api_key"] == "secret123"
end
			`,
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON := fmt.Sprintf(`{"lua_script": %q}`, tt.luaScript)
			var ruleObj rule.RequestRule
			if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
				t.Fatalf("Failed to compile Lua script: %v", err)
			}

			result := ruleObj.Match(req)
			if result != tt.shouldMatch {
				t.Errorf("Lua evaluation: expected %v, got %v", tt.shouldMatch, result)
			}
		})
	}
}

// TestRequestDataMapAccessInCEL verifies that CEL expressions can access
// the full RequestData.Data map via request['data'] and config via origin['params']
func TestRequestDataMapAccessInCEL(t *testing.T) {
	requestData := &reqctx.RequestData{
		ID: "req-1",
		OriginCtx: &reqctx.OriginContext{
			Params: map[string]any{
				"api_key": "secret123",
			},
		},
		Data: map[string]any{
			"custom_data": map[string]any{
				"value": "test",
			},
			"other_key": "direct_value",
		},
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	tests := []struct {
		name        string
		celExpr     string
		shouldMatch bool
	}{
		{
			name:        "Access via origin params",
			celExpr:     `origin['params']['api_key'] == "secret123"`,
			shouldMatch: true,
		},
		{
			name:        "Access custom_data via request data",
			celExpr:     `request['data']['custom_data']['value'] == "test"`,
			shouldMatch: true,
		},
		{
			name:        "Access direct value via request data",
			celExpr:     `request['data']['other_key'] == "direct_value"`,
			shouldMatch: true,
		},
		{
			name:        "Check key exists in origin params",
			celExpr:     `size(origin['params']) > 0`,
			shouldMatch: true,
		},
		{
			name:        "Access via origin params with null check",
			celExpr:     `size(origin['params']) > 0 && origin['params']['api_key'] == "secret123"`,
			shouldMatch: true,
		},
		{
			name:        "Non-existent key should not match",
			celExpr:     `'nonexistent' in request['data']`,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON := fmt.Sprintf(`{"cel_expr": %q}`, tt.celExpr)
			var ruleObj rule.RequestRule
			if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
				t.Fatalf("Failed to compile CEL expression: %v", err)
			}

			result := ruleObj.Match(req)
			if result != tt.shouldMatch {
				t.Errorf("CEL evaluation: expected %v, got %v for expr: %s",
					tt.shouldMatch, result, tt.celExpr)
			}
		})
	}
}

// TestRequestDataMapAccessInLua verifies that Lua scripts can access
// the full RequestData.Data map via ctx.data and config via origin.params
func TestRequestDataMapAccessInLua(t *testing.T) {
	requestData := &reqctx.RequestData{
		ID: "req-1",
		OriginCtx: &reqctx.OriginContext{
			Params: map[string]any{
				"api_key": "secret123",
			},
		},
		Data: map[string]any{
			"custom_data": map[string]any{
				"value": "test",
			},
			"other_key": "direct_value",
		},
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	tests := []struct {
		name        string
		luaScript   string
		shouldMatch bool
	}{
		{
			name: "Access via origin params",
			luaScript: `
function match_request(req, ctx)
	return origin ~= nil and origin.params ~= nil and
	       origin.params.api_key == "secret123"
end
			`,
			shouldMatch: true,
		},
		{
			name: "Access custom_data via ctx.request_data",
			luaScript: `
function match_request(req, ctx)
	return ctx.request_data ~= nil and
	       ctx.request_data.custom_data ~= nil and
	       ctx.request_data.custom_data.value == "test"
end
			`,
			shouldMatch: true,
		},
		{
			name: "Access direct value via ctx.request_data",
			luaScript: `
function match_request(req, ctx)
	return ctx.request_data ~= nil and
	       ctx.request_data.other_key == "direct_value"
end
			`,
			shouldMatch: true,
		},
		{
			name: "Access via origin params with null check",
			luaScript: `
function match_request(req, ctx)
	return origin ~= nil and origin.params ~= nil and
	       origin.params.api_key == "secret123"
end
			`,
			shouldMatch: true,
		},
		{
			name: "Check origin params exists",
			luaScript: `
function match_request(req, ctx)
	return origin ~= nil and origin.params ~= nil
end
			`,
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleJSON := fmt.Sprintf(`{"lua_script": %q}`, tt.luaScript)
			var ruleObj rule.RequestRule
			if err := json.Unmarshal([]byte(ruleJSON), &ruleObj); err != nil {
				t.Fatalf("Failed to compile Lua script: %v", err)
			}

			result := ruleObj.Match(req)
			if result != tt.shouldMatch {
				t.Errorf("Lua evaluation: expected %v, got %v", tt.shouldMatch, result)
			}
		})
	}
}

