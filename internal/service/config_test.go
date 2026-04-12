package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

func TestApplyConfigSection_NilConfig(t *testing.T) {
	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		StorageSettings: storage.Settings{Driver: "file", Params: map[string]string{"path": "/tmp/sites.json"}},
	}

	if err := applyConfigSection(); err != nil {
		t.Fatalf("applyConfigSection failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != "file" {
		t.Errorf("driver should be unchanged when config is nil, got %q", globalConfig.StorageSettings.Driver)
	}
}

func TestApplyConfigSection_EmptyConfig(t *testing.T) {
	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Config:          &ConfigSection{Origins: map[string]map[string]any{}, Source: nil},
		StorageSettings: storage.Settings{Driver: "file", Params: map[string]string{"path": "/tmp/sites.json"}},
	}

	if err := applyConfigSection(); err != nil {
		t.Fatalf("applyConfigSection failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != "file" {
		t.Errorf("driver should be unchanged when config has empty origins and nil source, got %q", globalConfig.StorageSettings.Driver)
	}
}

func TestApplyConfigSection_InlineWrapsExistingDriver(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Config: &ConfigSection{
			Origins: map[string]map[string]any{
				"api.test": {"id": "api", "hostname": "api.test", "action": map[string]any{"type": "proxy", "url": "https://example.com"}},
			},
		},
		StorageSettings: storage.Settings{
			Driver: "postgres",
			Params: map[string]string{"dsn": "postgres://localhost/test"},
		},
	}

	if err := applyConfigSection(); err != nil {
		t.Fatalf("applyConfigSection failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != storage.DriverComposite {
		t.Errorf("driver should be composite when wrapping postgres, got %q", globalConfig.StorageSettings.Driver)
	}
	if globalConfig.StorageSettings.Params["secondary_driver"] != "postgres" {
		t.Errorf("secondary_driver should be postgres, got %q", globalConfig.StorageSettings.Params["secondary_driver"])
	}
}

func TestApplyConfigSection_SourcePostgres(t *testing.T) {
	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Config: &ConfigSection{
			Source: &ConfigSource{
				Driver: "postgres",
				Params: map[string]string{"dsn": "postgres://user:pass@localhost:5432/db?sslmode=disable"},
			},
		},
	}

	if err := applyConfigSection(); err != nil {
		t.Fatalf("applyConfigSection failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != "postgres" {
		t.Errorf("driver should be postgres, got %q", globalConfig.StorageSettings.Driver)
	}
	if globalConfig.StorageSettings.Params["dsn"] != "postgres://user:pass@localhost:5432/db?sslmode=disable" {
		t.Errorf("dsn param mismatch, got %q", globalConfig.StorageSettings.Params["dsn"])
	}
}

func TestApplyConfigSection_SourceCDB(t *testing.T) {
	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Config: &ConfigSection{
			Source: &ConfigSource{
				Driver: storage.DriverCDB,
				Params: map[string]string{storage.ParamPath: "/var/lib/hosts.cdb"},
			},
		},
	}

	if err := applyConfigSection(); err != nil {
		t.Fatalf("applyConfigSection failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != storage.DriverCDB {
		t.Errorf("driver should be cdb, got %q", globalConfig.StorageSettings.Driver)
	}
	if globalConfig.StorageSettings.Params[storage.ParamPath] != "/var/lib/hosts.cdb" {
		t.Errorf("path param mismatch, got %q", globalConfig.StorageSettings.Params[storage.ParamPath])
	}
}

func TestApplyConfigSection_OriginsTakesPrecedenceOverSource(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Config: &ConfigSection{
			Origins: map[string]map[string]any{
				"inline.test": {"id": "inline", "hostname": "inline.test"},
			},
			Source: &ConfigSource{Path: "/tmp/sites.json"},
		},
		StorageSettings: storage.Settings{Driver: "", Params: make(map[string]string)},
	}

	if err := applyConfigSection(); err != nil {
		t.Fatalf("applyConfigSection failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != storage.DriverLocal {
		t.Errorf("origins should take precedence; driver should be local, got %q", globalConfig.StorageSettings.Driver)
	}
	if len(globalConfig.Origins) != 1 {
		t.Errorf("expected 1 origin from inline, got %d", len(globalConfig.Origins))
	}
}

func TestConfigSourceToStorageSettings_Nil(t *testing.T) {
	settings := configSourceToStorageSettings(nil)
	if settings.Driver != "" {
		t.Errorf("nil input should return empty driver, got %q", settings.Driver)
	}
	if len(settings.Params) > 0 {
		t.Errorf("nil input should return empty params, got %v", settings.Params)
	}
}

func TestConfigSourceToStorageSettings_DriverAndParamsOnly(t *testing.T) {
	settings := configSourceToStorageSettings(&ConfigSource{
		Driver: storage.DriverSQLite,
		Params: map[string]string{storage.ParamPath: "/var/origins.db"},
	})
	if settings.Driver != storage.DriverSQLite {
		t.Errorf("driver = %q, want sqlite", settings.Driver)
	}
	if settings.Params[storage.ParamPath] != "/var/origins.db" {
		t.Errorf("path = %q, want /var/origins.db", settings.Params[storage.ParamPath])
	}
}

func TestConfigSourceToStorageSettings_PathTakesPrecedenceOverDriver(t *testing.T) {
	settings := configSourceToStorageSettings(&ConfigSource{
		Driver: "postgres",
		Params: map[string]string{"dsn": "postgres://localhost/db"},
		Path:   "/var/sites.json",
	})
	if settings.Driver != storage.DriverFile {
		t.Errorf("path shorthand should override driver; driver = %q, want file", settings.Driver)
	}
	if settings.Params[storage.ParamPath] != "/var/sites.json" {
		t.Errorf("path = %q, want /var/sites.json", settings.Params[storage.ParamPath])
	}
}

func TestLoadConfig_WithConfigSectionInline(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "sb.yml")
	configYAML := `
config:
  origins:
    localhost:
      id: config-test
      hostname: localhost
      action:
        type: proxy
        url: https://example.com
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	if err := LoadConfig(tmpDir, "sb.yml"); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(globalConfig.Origins) != 1 {
		t.Errorf("expected 1 origin from config section, got %d", len(globalConfig.Origins))
	}
	if _, ok := globalConfig.Origins["localhost"]; !ok {
		var keys []string
		for k := range globalConfig.Origins {
			keys = append(keys, k)
		}
		t.Errorf("expected origin localhost, got keys %v", keys)
	}
	if globalConfig.StorageSettings.Driver != storage.DriverLocal {
		t.Errorf("driver should be local for inline config, got %q", globalConfig.StorageSettings.Driver)
	}

	// Verify loadLocalOrigins seeds storage (full flow)
	if err := loadLocalOrigins(); err != nil {
		t.Fatalf("loadLocalOrigins failed: %v", err)
	}
	stor, err := storage.NewStorage(globalConfig.StorageSettings)
	if err != nil {
		t.Fatalf("NewStorage failed: %v", err)
	}
	defer stor.Close()
	ctx := context.Background()
	data, err := stor.Get(ctx, "localhost")
	if err != nil {
		t.Fatalf("Get localhost from storage failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty config data from storage")
	}
}

func TestLoadConfig_WithConfigSectionSourcePath(t *testing.T) {
	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "sb.yml")
	configYAML := `
config:
  source:
    path: ./config/sites/sites.json
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	if err := LoadConfig(tmpDir, "sb.yml"); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != storage.DriverFile {
		t.Errorf("driver should be file, got %q", globalConfig.StorageSettings.Driver)
	}
	if globalConfig.StorageSettings.Params[storage.ParamPath] != "./config/sites/sites.json" {
		t.Errorf("path = %q, want ./config/sites/sites.json", globalConfig.StorageSettings.Params[storage.ParamPath])
	}
	if globalConfig.Origins != nil {
		t.Error("origins should be nil when using external source")
	}
}
