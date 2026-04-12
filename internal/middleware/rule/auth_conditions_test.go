package rule

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestAuthConditions_Match(t *testing.T) {
	tests := []struct {
		name          string
		conditions    AuthConditions
		authData      *reqctx.AuthData
		expectedMatch bool
	}{
		{
			name: "Match exact email",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "email",
							Value: "user@example.com",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "user@example.com",
				},
			},
			expectedMatch: true,
		},
		{
			name: "No match wrong email",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "email",
							Value: "admin@example.com",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "user@example.com",
				},
			},
			expectedMatch: false,
		},
		{
			name: "Match nested path",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "user.department",
							Value: "engineering",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"user": map[string]any{
						"department": "engineering",
					},
				},
			},
			expectedMatch: true,
		},
		{
			name: "Match array element",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "roles.0",
							Value: "admin",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"roles": []any{"admin", "user"},
				},
			},
			expectedMatch: true,
		},
		{
			name: "Match one of many values",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:   "role",
							Values: []string{"admin", "moderator", "editor"},
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"role": "moderator",
				},
			},
			expectedMatch: true,
		},
		{
			name: "Match contains",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:     "email",
							Contains: "@company.com",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"email": "user@company.com",
				},
			},
			expectedMatch: true,
		},
		{
			name: "Match starts with",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:       "user_id",
							StartsWith: "admin_",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"user_id": "admin_12345",
				},
			},
			expectedMatch: true,
		},
		{
			name: "Match ends with",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:     "domain",
							EndsWith: ".internal",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"domain": "api.company.internal",
				},
			},
			expectedMatch: true,
		},
		{
			name: "Match multiple rules (AND logic)",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "department",
							Value: "engineering",
						},
						{
							Path:   "role",
							Values: []string{"admin", "lead"},
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"department": "engineering",
					"role":       "admin",
				},
			},
			expectedMatch: true,
		},
		{
			name: "Multiple rules - one fails (AND logic)",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "department",
							Value: "engineering",
						},
						{
							Path:  "role",
							Value: "admin",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"department": "engineering",
					"role":       "user", // This doesn't match
				},
			},
			expectedMatch: false,
		},
		{
			name: "Multiple conditions (OR logic)",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "role",
							Value: "admin",
						},
					},
				},
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "role",
							Value: "moderator",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"role": "moderator",
				},
			},
			expectedMatch: true,
		},
		{
			name: "Match auth type",
			conditions: AuthConditions{
				{
					Type: "oauth",
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "provider",
							Value: "google",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"provider": "google",
				},
			},
			expectedMatch: true,
		},
		{
			name: "No match wrong auth type",
			conditions: AuthConditions{
				{
					Type: "jwt",
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "sub",
							Value: "user123",
						},
					},
				},
			},
			authData: &reqctx.AuthData{
				Type: "oauth",
				Data: map[string]any{
					"sub": "user123",
				},
			},
			expectedMatch: false,
		},
		{
			name: "Nil auth data",
			conditions: AuthConditions{
				{
					AuthConditionRules: []AuthConditionRule{
						{
							Path:  "email",
							Value: "user@example.com",
						},
					},
				},
			},
			authData:      nil,
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.conditions.match(tt.authData)
			if match != tt.expectedMatch {
				t.Errorf("Expected match=%v, got %v", tt.expectedMatch, match)
			}
		})
	}
}

func TestExtractValueFromPath(t *testing.T) {
	tests := []struct {
		name          string
		data          map[string]any
		path          string
		expectedValue any
	}{
		{
			name: "Simple path",
			data: map[string]any{
				"email": "user@example.com",
			},
			path:          "email",
			expectedValue: "user@example.com",
		},
		{
			name: "Nested path",
			data: map[string]any{
				"user": map[string]any{
					"email": "user@example.com",
				},
			},
			path:          "user.email",
			expectedValue: "user@example.com",
		},
		{
			name: "Array index",
			data: map[string]any{
				"roles": []any{"admin", "user"},
			},
			path:          "roles.0",
			expectedValue: "admin",
		},
		{
			name: "Deep nesting",
			data: map[string]any{
				"company": map[string]any{
					"department": map[string]any{
						"name": "engineering",
					},
				},
			},
			path:          "company.department.name",
			expectedValue: "engineering",
		},
		{
			name: "Path not found",
			data: map[string]any{
				"email": "user@example.com",
			},
			path:          "name",
			expectedValue: nil,
		},
		{
			name: "Empty path",
			data: map[string]any{
				"email": "user@example.com",
			},
			path:          "",
			expectedValue: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := extractValueFromPath(tt.data, tt.path)
			if value != tt.expectedValue {
				t.Errorf("Expected value=%v, got %v", tt.expectedValue, value)
			}
		})
	}
}
