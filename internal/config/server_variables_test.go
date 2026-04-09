package config

import (
	"strings"
	"testing"
)

func TestBuildServerVariables(t *testing.T) {
	t.Run("built-in fields populated", func(t *testing.T) {
		vars, err := BuildServerVariables(
			"inst-1", "1.0.0", "abc123", "2026-01-01T00:00:00Z", "myhost", "production",
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		checks := map[string]string{
			"instance_id": "inst-1",
			"version":     "1.0.0",
			"build_hash":  "abc123",
			"start_time":  "2026-01-01T00:00:00Z",
			"hostname":    "myhost",
			"environment": "production",
		}
		for k, want := range checks {
			got, ok := vars[k].(string)
			if !ok {
				t.Errorf("vars[%q] not a string", k)
				continue
			}
			if got != want {
				t.Errorf("vars[%q] = %q, want %q", k, got, want)
			}
		}
	})

	t.Run("custom variables merged", func(t *testing.T) {
		custom := map[string]string{
			"region":      "us-east-1",
			"deploy_slot": "blue",
		}
		vars, err := BuildServerVariables(
			"inst-1", "1.0.0", "", "", "host", "staging",
			custom,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vars["region"] != "us-east-1" {
			t.Errorf("region = %v, want us-east-1", vars["region"])
		}
		if vars["deploy_slot"] != "blue" {
			t.Errorf("deploy_slot = %v, want blue", vars["deploy_slot"])
		}
		// Built-in still present
		if vars["version"] != "1.0.0" {
			t.Errorf("version = %v, want 1.0.0", vars["version"])
		}
	})

	t.Run("custom key colliding with built-in rejected", func(t *testing.T) {
		for _, key := range []string{"version", "hostname", "instance_id", "environment", "build_hash", "start_time"} {
			custom := map[string]string{key: "override"}
			_, err := BuildServerVariables("", "", "", "", "", "", custom)
			if err == nil {
				t.Errorf("expected error for custom key %q colliding with built-in", key)
			} else if !strings.Contains(err.Error(), "collides with built-in") {
				t.Errorf("error for key %q = %q, want 'collides with built-in'", key, err.Error())
			}
		}
	})

	t.Run("nil custom is fine", func(t *testing.T) {
		vars, err := BuildServerVariables("id", "v", "h", "t", "host", "env", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vars) != 6 {
			t.Errorf("expected 6 built-in vars, got %d", len(vars))
		}
	})
}

func TestSetAndGetServerVariables(t *testing.T) {
	// Reset to clean state
	SetServerVariables(nil)
	if got := GetServerVariables(); got != nil {
		t.Error("expected nil after reset")
	}

	vars := map[string]any{"version": "1.0.0", "hostname": "testhost"}
	SetServerVariables(vars)

	got := GetServerVariables()
	if got == nil {
		t.Fatal("expected non-nil after set")
	}
	if got["version"] != "1.0.0" {
		t.Errorf("version = %v, want 1.0.0", got["version"])
	}

	// Clean up
	SetServerVariables(nil)
}
