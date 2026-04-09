package config

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestGetConfigParams_VersionNotOverwritten(t *testing.T) {
	parent := &Config{
		ID:       "parent-config",
		Hostname: "parent.example.com",
		Version:  "2.0",
		WorkspaceID: "tenant-1",
	}
	child := &Config{
		ID:       "child-config",
		Hostname: "child.internal",
		Version:  "1.0",
		Parent:   parent,
	}

	params := child.GetConfigParams(context.Background())

	// Child version should be preserved
	if got := params[reqctx.ConfigParamVersion]; got != "1.0" {
		t.Errorf("ConfigParamVersion = %q, want %q", got, "1.0")
	}

	// Parent version should be in its own key
	if got := params[reqctx.ConfigParamParentVersion]; got != "2.0" {
		t.Errorf("ConfigParamParentVersion = %q, want %q", got, "2.0")
	}

	// Other parent fields should still be set
	if got := params[reqctx.ConfigParamParentID]; got != "parent-config" {
		t.Errorf("ConfigParamParentID = %q, want %q", got, "parent-config")
	}
	if got := params[reqctx.ConfigParamParentHostname]; got != "parent.example.com" {
		t.Errorf("ConfigParamParentHostname = %q, want %q", got, "parent.example.com")
	}
}

func TestGetConfigParams_NoParent(t *testing.T) {
	cfg := &Config{
		ID:       "standalone",
		Hostname: "standalone.example.com",
		Version:  "3.5",
	}

	params := cfg.GetConfigParams(context.Background())

	if got := params[reqctx.ConfigParamVersion]; got != "3.5" {
		t.Errorf("ConfigParamVersion = %q, want %q", got, "3.5")
	}

	// Parent version should not be set
	if _, exists := params[reqctx.ConfigParamParentVersion]; exists {
		t.Error("ConfigParamParentVersion should not be set when no parent exists")
	}
}

func TestGetParentVersion(t *testing.T) {
	tests := []struct {
		name     string
		params   reqctx.ConfigParams
		expected string
	}{
		{
			name:     "nil params",
			params:   nil,
			expected: "",
		},
		{
			name:     "no parent version",
			params:   reqctx.ConfigParams{"version": "1.0"},
			expected: "",
		},
		{
			name:     "has parent version",
			params:   reqctx.ConfigParams{"parent_version": "2.0"},
			expected: "2.0",
		},
		{
			name:     "both versions present",
			params:   reqctx.ConfigParams{"version": "1.0", "parent_version": "2.0"},
			expected: "2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.params.GetParentVersion(); got != tt.expected {
				t.Errorf("GetParentVersion() = %q, want %q", got, tt.expected)
			}
		})
	}
}
