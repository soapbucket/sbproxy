package service

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

func TestLoadLocalOrigins_NoOrigins(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	// Save original config
	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Origins: map[string]map[string]any{},
	}

	if err := loadLocalOrigins(); err != nil {
		t.Fatalf("loadLocalOrigins failed: %v", err)
	}

	// Should not change driver when Origins is empty
	if globalConfig.StorageSettings.Driver != "" {
		t.Errorf("driver should not change when Origins is empty, got %q", globalConfig.StorageSettings.Driver)
	}
}

func TestLoadLocalOrigins_SetsDriverLocal(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Origins: map[string]map[string]any{
			"test.example.com": {"id": "test-1", "name": "Test"},
		},
		StorageSettings: storage.Settings{
			Driver: "",
			Params: make(map[string]string),
		},
	}

	if err := loadLocalOrigins(); err != nil {
		t.Fatalf("loadLocalOrigins failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != storage.DriverLocal {
		t.Errorf("driver should be set to local, got %q", globalConfig.StorageSettings.Driver)
	}
}

func TestLoadLocalOrigins_KeepsDriverLocal(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Origins: map[string]map[string]any{
			"test.example.com": {"id": "test-1", "name": "Test"},
		},
		StorageSettings: storage.Settings{
			Driver: storage.DriverLocal,
			Params: make(map[string]string),
		},
	}

	if err := loadLocalOrigins(); err != nil {
		t.Fatalf("loadLocalOrigins failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != storage.DriverLocal {
		t.Errorf("driver should remain local, got %q", globalConfig.StorageSettings.Driver)
	}
}

func TestLoadLocalOrigins_WrapsExistingDriver(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Origins: map[string]map[string]any{
			"test.example.com": {"id": "test-1", "name": "Test"},
		},
		StorageSettings: storage.Settings{
			Driver: "postgres",
			Params: map[string]string{
				"dsn": "postgres://localhost/test",
			},
		},
	}

	if err := loadLocalOrigins(); err != nil {
		t.Fatalf("loadLocalOrigins failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != storage.DriverComposite {
		t.Errorf("driver should be composite, got %q", globalConfig.StorageSettings.Driver)
	}

	// Verify params contain the secondary driver info
	if globalConfig.StorageSettings.Params["secondary_driver"] != "postgres" {
		t.Errorf("secondary_driver param should be postgres, got %q", globalConfig.StorageSettings.Params["secondary_driver"])
	}

	if globalConfig.StorageSettings.Params["secondary_dsn"] != "postgres://localhost/test" {
		t.Errorf("secondary_dsn param mismatch, got %q", globalConfig.StorageSettings.Params["secondary_dsn"])
	}
}

func TestLoadLocalOrigins_JSONMarshalError(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	// Create an origin config with a value that can't be marshaled to JSON
	// Use a channel which is not JSON-serializable
	globalConfig = Config{
		Origins: map[string]map[string]any{
			"test.example.com": {
				"id": "test-1",
				"ch": make(chan int), // channels can't be marshaled to JSON
			},
		},
		StorageSettings: storage.Settings{
			Driver: "",
			Params: make(map[string]string),
		},
	}

	if err := loadLocalOrigins(); err == nil {
		t.Fatalf("loadLocalOrigins should fail with unmarshallable value")
	}
}

func TestLoadLocalOrigins_MultipleOrigins(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Origins: map[string]map[string]any{
			"api.example.com": {"id": "api", "name": "API"},
			"web.example.com": {"id": "web", "name": "Web"},
		},
		StorageSettings: storage.Settings{
			Driver: "",
			Params: make(map[string]string),
		},
	}

	if err := loadLocalOrigins(); err != nil {
		t.Fatalf("loadLocalOrigins failed: %v", err)
	}

	// Verify storage was seeded with both origins
	// We can't directly check the storage, but we verified no error occurred
	if globalConfig.StorageSettings.Driver != storage.DriverLocal {
		t.Errorf("driver should be local, got %q", globalConfig.StorageSettings.Driver)
	}
}

func TestApplyConfigSection_InlineOrigins(t *testing.T) {
	defer storage.SetLocalOrigins(nil)

	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Config: &ConfigSection{
			Origins: map[string]map[string]any{
				"api.test": {"id": "api", "hostname": "api.test", "action": map[string]any{"type": "proxy", "url": "https://example.com"}},
			},
		},
		StorageSettings: storage.Settings{Driver: "", Params: make(map[string]string)},
	}

	if err := applyConfigSection(); err != nil {
		t.Fatalf("applyConfigSection failed: %v", err)
	}

	if len(globalConfig.Origins) != 1 {
		t.Errorf("expected 1 origin, got %d", len(globalConfig.Origins))
	}
	if globalConfig.StorageSettings.Driver != storage.DriverLocal {
		t.Errorf("driver should be local for inline config, got %q", globalConfig.StorageSettings.Driver)
	}
}

func TestApplyConfigSection_SourcePath(t *testing.T) {
	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Config: &ConfigSection{
			Source: &ConfigSource{Path: "./config/sites/sites.json"},
		},
		Origins: map[string]map[string]any{"old": {"id": "old"}},
	}

	if err := applyConfigSection(); err != nil {
		t.Fatalf("applyConfigSection failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != storage.DriverFile {
		t.Errorf("driver should be file, got %q", globalConfig.StorageSettings.Driver)
	}
	if globalConfig.StorageSettings.Params[storage.ParamPath] != "./config/sites/sites.json" {
		t.Errorf("path param mismatch, got %q", globalConfig.StorageSettings.Params[storage.ParamPath])
	}
	if globalConfig.Origins != nil {
		t.Error("origins should be nil when using external source")
	}
}

func TestApplyConfigSection_SourceDriverParams(t *testing.T) {
	origConfig := globalConfig
	defer func() { globalConfig = origConfig }()

	globalConfig = Config{
		Config: &ConfigSection{
			Source: &ConfigSource{
				Driver: storage.DriverFile,
				Params: map[string]string{storage.ParamPath: "/tmp/sites.json"},
			},
		},
	}

	if err := applyConfigSection(); err != nil {
		t.Fatalf("applyConfigSection failed: %v", err)
	}

	if globalConfig.StorageSettings.Driver != storage.DriverFile {
		t.Errorf("driver should be file, got %q", globalConfig.StorageSettings.Driver)
	}
	if globalConfig.StorageSettings.Params[storage.ParamPath] != "/tmp/sites.json" {
		t.Errorf("path param mismatch, got %q", globalConfig.StorageSettings.Params[storage.ParamPath])
	}
}

func TestConfigSourceToStorageSettings_PathShorthand(t *testing.T) {
	settings := configSourceToStorageSettings(&ConfigSource{Path: "/var/sites.json"})
	if settings.Driver != storage.DriverFile {
		t.Errorf("driver = %q, want file", settings.Driver)
	}
	if settings.Params[storage.ParamPath] != "/var/sites.json" {
		t.Errorf("path = %q, want /var/sites.json", settings.Params[storage.ParamPath])
	}
}

func TestConfigSourceToStorageSettings_URLShorthand(t *testing.T) {
	settings := configSourceToStorageSettings(&ConfigSource{URL: "https://api.example.com/origins"})
	if settings.Driver != "http" {
		t.Errorf("driver = %q, want http", settings.Driver)
	}
	if settings.Params["url"] != "https://api.example.com/origins" {
		t.Errorf("url = %q, want https://api.example.com/origins", settings.Params["url"])
	}
}
