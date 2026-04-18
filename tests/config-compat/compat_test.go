// Package configcompat validates YAML fixture files against the config parser
// to ensure backward compatibility across config schema versions.
package configcompat

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/soapbucket/sbproxy/internal/config"
)

// fixturesDir returns the absolute path to the fixtures directory relative to this test file.
func fixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "fixtures")
}

// loadFixture reads and parses a YAML fixture file through the config loader.
func loadFixture(t *testing.T, name string) *config.Config {
	t.Helper()
	path := filepath.Join(fixturesDir(t), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	cfg, err := config.Load(data)
	if err != nil {
		t.Fatalf("failed to parse fixture %s: %v", name, err)
	}
	return cfg
}

func TestBasicProxy(t *testing.T) {
	cfg := loadFixture(t, "basic-proxy.yml")

	if cfg.ID != "basic-proxy-1" {
		t.Errorf("expected ID 'basic-proxy-1', got %q", cfg.ID)
	}
	if cfg.Hostname != "api.example.com" {
		t.Errorf("expected Hostname 'api.example.com', got %q", cfg.Hostname)
	}
	if cfg.WorkspaceID != "ws-test-001" {
		t.Errorf("expected WorkspaceID 'ws-test-001', got %q", cfg.WorkspaceID)
	}
	if cfg.Version != "1.0" {
		t.Errorf("expected Version '1.0', got %q", cfg.Version)
	}
	if cfg.ConfigVersion != 2 {
		t.Errorf("expected ConfigVersion 2, got %d", cfg.ConfigVersion)
	}
}

func TestFullFeatures(t *testing.T) {
	cfg := loadFixture(t, "full-features.yml")

	if cfg.ID != "full-features-1" {
		t.Errorf("expected ID 'full-features-1', got %q", cfg.ID)
	}
	if cfg.Hostname != "full.example.com" {
		t.Errorf("expected Hostname 'full.example.com', got %q", cfg.Hostname)
	}
	if cfg.Environment != "prod" {
		t.Errorf("expected Environment 'prod', got %q", cfg.Environment)
	}
	if len(cfg.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(cfg.Tags))
	}
	if !cfg.ForceSSL {
		t.Error("expected ForceSSL to be true")
	}
	if len(cfg.AllowedMethods) != 4 {
		t.Errorf("expected 4 allowed methods, got %d", len(cfg.AllowedMethods))
	}
	if len(cfg.Variables) != 2 {
		t.Errorf("expected 2 variables, got %d", len(cfg.Variables))
	}
	if cfg.ConfigVersion != 2 {
		t.Errorf("expected ConfigVersion 2, got %d", cfg.ConfigVersion)
	}
}

func TestAIGateway(t *testing.T) {
	cfg := loadFixture(t, "ai-gateway.yml")

	if cfg.ID != "ai-gateway-1" {
		t.Errorf("expected ID 'ai-gateway-1', got %q", cfg.ID)
	}
	if cfg.Hostname != "ai.example.com" {
		t.Errorf("expected Hostname 'ai.example.com', got %q", cfg.Hostname)
	}
	if cfg.WorkspaceID != "ws-test-003" {
		t.Errorf("expected WorkspaceID 'ws-test-003', got %q", cfg.WorkspaceID)
	}
	// The action field should be parsed as raw JSON
	if cfg.Action == nil {
		t.Error("expected Action to be non-nil")
	}
	// Auth should be parsed
	if cfg.Auth == nil {
		t.Error("expected Auth to be non-nil")
	}
	// Should have one policy
	if len(cfg.Policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(cfg.Policies))
	}
	if cfg.ConfigVersion != 2 {
		t.Errorf("expected ConfigVersion 2, got %d", cfg.ConfigVersion)
	}
}

func TestConfigVersionValidation(t *testing.T) {
	tests := []struct {
		name    string
		version int
		wantErr bool
	}{
		{"zero (missing) is allowed with warning", 0, false},
		{"version 1 is valid", 1, false},
		{"version 2 is valid", 2, false},
		{"version 3 is unsupported", 3, true},
		{"negative version is unsupported", -1, true},
		{"large version is unsupported", 99, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := config.ValidateConfigVersion(tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfigVersion(%d) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
		})
	}
}

func TestAllFixturesParse(t *testing.T) {
	dir := fixturesDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read fixtures dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			loadFixture(t, name)
		})
	}
}
