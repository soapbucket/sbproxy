package config

import (
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/vault"
)

func TestValidateVariables(t *testing.T) {
	tests := []struct {
		name      string
		variables map[string]any
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid simple variables",
			variables: map[string]any{
				"api_url":     "https://api.example.com",
				"max_retries": 3,
				"debug":       true,
			},
			wantErr: false,
		},
		{
			name: "valid nested variables",
			variables: map[string]any{
				"endpoints": map[string]any{
					"users":  "/api/v2/users",
					"orders": "/api/v2/orders",
				},
			},
			wantErr: false,
		},
		{
			name: "valid underscore prefix",
			variables: map[string]any{
				"_internal": "value",
			},
			wantErr: false,
		},
		{
			name: "invalid key with dot",
			variables: map[string]any{
				"foo.bar": "value",
			},
			wantErr: true,
			errMsg:  "invalid variable key",
		},
		{
			name: "invalid key with hyphen",
			variables: map[string]any{
				"foo-bar": "value",
			},
			wantErr: true,
			errMsg:  "invalid variable key",
		},
		{
			name: "invalid key starting with number",
			variables: map[string]any{
				"1invalid": "value",
			},
			wantErr: true,
			errMsg:  "invalid variable key",
		},
		{
			name: "reserved name - request",
			variables: map[string]any{
				"request": "value",
			},
			wantErr: true,
			errMsg:  "reserved context name",
		},
		{
			name: "reserved name - config",
			variables: map[string]any{
				"config": "value",
			},
			wantErr: true,
			errMsg:  "reserved context name",
		},
		{
			name: "reserved name - secrets",
			variables: map[string]any{
				"secrets": "value",
			},
			wantErr: true,
			errMsg:  "reserved context name",
		},
		{
			name: "reserved name - session",
			variables: map[string]any{
				"session": "value",
			},
			wantErr: true,
			errMsg:  "reserved context name",
		},
		{
			name: "reserved name - var",
			variables: map[string]any{
				"var": "value",
			},
			wantErr: true,
			errMsg:  "reserved context name",
		},
		{
			name: "reserved name - server",
			variables: map[string]any{
				"server": "value",
			},
			wantErr: true,
			errMsg:  "reserved context name",
		},
		{
			name: "reserved name - env",
			variables: map[string]any{
				"env": "value",
			},
			wantErr: true,
			errMsg:  "reserved context name",
		},
		{
			name: "reserved name - feature",
			variables: map[string]any{
				"feature": "value",
			},
			wantErr: true,
			errMsg:  "reserved context name",
		},
		{
			name:      "empty map is valid",
			variables: map[string]any{},
			wantErr:   false,
		},
		{
			name:      "nil map is valid",
			variables: nil,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := vault.ValidateVariables(tt.variables)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
