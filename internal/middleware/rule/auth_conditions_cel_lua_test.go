package rule

import (
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestAuthConditionRule_CEL(t *testing.T) {
	tests := []struct {
		name        string
		celExpr     string
		authData    *reqctx.AuthData
		shouldMatch bool
	}{
		{
			name:    "CEL matches user email",
			celExpr: `session.auth.data.email == "admin@example.com"`,
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
			celExpr: `session.auth.data.email == "admin@example.com"`,
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
			name:    "CEL matches auth type",
			celExpr: `session.auth.type == "oauth"`,
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
			name:    "CEL checks is_authenticated",
			celExpr: `session.is_authenticated == true`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "admin@example.com",
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
	tests := []struct {
		name        string
		luaScript   string
		authData    *reqctx.AuthData
		shouldMatch bool
	}{
		{
			name:      "Lua matches via path-based rule (email match)",
			luaScript: `function match_request(req, ctx) return true end`,
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
			name:      "Lua returns false",
			luaScript: `function match_request(req, ctx) return false end`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "admin@example.com",
				},
			},
			shouldMatch: false,
		},
		{
			name:      "Lua checks request path",
			luaScript: `function match_request(req, ctx) return req.path == "/" end`,
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "user@example.com",
				},
			},
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &AuthConditionRule{
				LuaScript: tt.luaScript,
			}

			// Initialize via JSON unmarshaling
			jsonData, err := json.Marshal(map[string]string{"lua_script": tt.luaScript})
			if err != nil {
				t.Fatalf("failed to marshal JSON: %v", err)
			}

			err = rule.UnmarshalJSON(jsonData)
			if err != nil {
				t.Fatalf("failed to initialize Lua matcher: %v", err)
			}

			result := rule.match(tt.authData)
			if result != tt.shouldMatch {
				t.Errorf("expected %v, got %v", tt.shouldMatch, result)
			}
		})
	}
}

func TestAuthConditionRule_MixedMatching(t *testing.T) {
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
		// CEL takes precedence - checks session.is_authenticated which will be true
		err := json.Unmarshal([]byte(`{
			"path": "email",
			"value": "user@example.com",
			"cel_expr": "session.is_authenticated == true"
		}`), &AuthConditionRule{})
		// Check it compiles
		if err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		rule := &AuthConditionRule{}
		err = rule.UnmarshalJSON([]byte(`{
			"path": "email",
			"value": "user@example.com",
			"cel_expr": "session.is_authenticated == true"
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
