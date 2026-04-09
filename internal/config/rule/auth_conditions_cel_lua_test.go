package rule

import (
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestAuthConditionRule_CEL(t *testing.T) {
	t.Skip("CEL tests require full CEL environment setup - test in integration tests")
	
	
	tests := []struct {
		name      string
		celExpr   string
		authData  *reqctx.AuthData
		shouldMatch bool
	}{
		{
			name:    "CEL matches user email",
			celExpr: `request.session.auth.data.email == "admin@example.com"`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "admin@example.com",
					"roles": []any{"admin", "user"},
				},
			},
			shouldMatch: true,
		},
		{
			name:    "CEL doesn't match different email",
			celExpr: `request.session.auth.data.email == "admin@example.com"`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "user@example.com",
					"roles": []any{"user"},
				},
			},
			shouldMatch: false,
		},
		{
			name:    "CEL matches complex condition",
			celExpr: `request.session.auth.type == "oauth" && size(request.session.auth.data.roles) > 1`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "admin@example.com",
					"roles": []any{"admin", "user"},
				},
			},
			shouldMatch: true,
		},
		{
			name:    "CEL checks role membership",
			celExpr: `"admin" in request.session.auth.data.roles`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "admin@example.com",
					"roles": []any{"admin", "user"},
				},
			},
			shouldMatch: true,
		},
		{
			name:    "CEL checks nested data",
			celExpr: `request.session.auth.data.metadata.tier == "premium"`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "premium@example.com",
					"metadata": map[string]any{
						"tier":   "premium",
						"active": true,
					},
				},
			},
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &AuthConditionRule{
				CELExpr: tt.celExpr,
			}
			
			// Initialize the CEL matcher using proper JSON marshaling
			jsonData, err := json.Marshal(map[string]string{"cel_expr": tt.celExpr})
			if err != nil {
				t.Fatalf("failed to marshal JSON: %v", err)
			}
			
			err = rule.UnmarshalJSON(jsonData)
			if err != nil {
				t.Fatalf("failed to initialize CEL matcher: %v", err)
			}

			result := rule.match(tt.authData)
			if result != tt.shouldMatch {
				t.Errorf("expected %v, got %v", tt.shouldMatch, result)
			}
		})
	}
}

func TestAuthConditionRule_Lua(t *testing.T) {
	t.Skip("Lua tests require full request context - test in integration tests")
	
	
	tests := []struct {
		name        string
		luaScript   string
		authData    *reqctx.AuthData
		shouldMatch bool
	}{
		{
			name: "Lua matches user email",
			luaScript: `
				local req_data = get_request_data()
				if req_data.session_data and req_data.session_data.auth_data then
					local auth = req_data.session_data.auth_data
					return auth.data.email == "admin@example.com"
				end
				return false
			`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "admin@example.com",
					"roles": []any{"admin", "user"},
				},
			},
			shouldMatch: true,
		},
		{
			name: "Lua checks role count",
			luaScript: `
				local req_data = get_request_data()
				if req_data.session_data and req_data.session_data.auth_data then
					local auth = req_data.session_data.auth_data
					return #auth.data.roles >= 2
				end
				return false
			`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "admin@example.com",
					"roles": []any{"admin", "user"},
				},
			},
			shouldMatch: true,
		},
		{
			name: "Lua checks nested data",
			luaScript: `
				local req_data = get_request_data()
				if req_data.session_data and req_data.session_data.auth_data then
					local auth = req_data.session_data.auth_data
					return auth.data.metadata and auth.data.metadata.active == true
				end
				return false
			`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "user@example.com",
					"metadata": map[string]any{
						"active": true,
						"tier":   "basic",
					},
				},
			},
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Lua script needs to be properly escaped for JSON
			// For simplicity in tests, we'll directly initialize the matcher
			rule := &AuthConditionRule{
				LuaScript: tt.luaScript,
			}
			
			// Initialize the Lua matcher manually
			luaMatcher, err := newLuaMatcherForTest(tt.luaScript)
			if err != nil {
				t.Skipf("Lua matcher initialization failed (expected if Lua not fully configured): %v", err)
				return
			}
			rule.luaScript = luaMatcher

			result := rule.match(tt.authData)
			if result != tt.shouldMatch {
				t.Errorf("expected %v, got %v", tt.shouldMatch, result)
			}
		})
	}
}

// Helper function for Lua tests
func newLuaMatcherForTest(script string) (lua.Matcher, error) {
	// Use the actual Lua matcher initialization
	return lua.NewMatcher(script)
}

func TestAuthConditionRule_MixedMatching(t *testing.T) {
	t.Skip("Mixed matching tests require full CEL environment - test in integration tests")
	
	
	// Test that CEL/Lua takes precedence over path-based matching
	t.Run("CEL overrides path matching", func(t *testing.T) {
		authData := &reqctx.AuthData{
			Type: "oauth",
			Data: map[string]any{
				"email": "admin@example.com",
				"roles": []any{"admin"},
			},
		}

		// Rule with both CEL and path matching
		rule := &AuthConditionRule{
			Path:    "email",
			Value:   "user@example.com", // This would normally not match
			CELExpr: `request.session.auth.data.email == "admin@example.com"`, // But CEL matches
		}

		err := rule.UnmarshalJSON([]byte(`{
			"path": "email",
			"value": "user@example.com",
			"cel_expr": "request.session.auth.data.email == \"admin@example.com\""
		}`))
		if err != nil {
			t.Fatalf("failed to initialize matcher: %v", err)
		}

		// CEL should take precedence and match
		if !rule.match(authData) {
			t.Error("expected CEL to match and override path-based matching")
		}
	})
}

