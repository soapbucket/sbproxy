package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestNewSettingsFromDSN tests DSN parsing
func TestNewSettingsFromDSN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		dsn        string
		wantDriver string
		wantParams map[string]string
		wantErr    bool
	}{
		{
			name:       "postgres DSN",
			dsn:        "postgres://user:pass@localhost:5432/dbname?sslmode=disable",
			wantDriver: DriverPostgres,
			wantParams: map[string]string{
				ParamDSN: "postgres://user:pass@localhost:5432/dbname?sslmode=disable",
			},
			wantErr: false,
		},
		{
			name:       "sqlite DSN",
			dsn:        "sqlite:///path/to/database.db",
			wantDriver: DriverSQLite,
			wantParams: map[string]string{
				ParamPath: "/path/to/database.db",
			},
			wantErr: false,
		},
		{
			name:       "file DSN",
			dsn:        "file:///path/to/file.json",
			wantDriver: DriverFile,
			wantParams: map[string]string{
				ParamPath: "/path/to/file.json",
			},
			wantErr: false,
		},
		{
			name:       "cdb DSN",
			dsn:        "cdb:///path/to/file.cdb",
			wantDriver: DriverCDB,
			wantParams: map[string]string{
				ParamPath: "/path/to/file.cdb",
			},
			wantErr: false,
		},
		{
			name:       "plain path defaults to sqlite",
			dsn:        "/path/to/database.db",
			wantDriver: DriverSQLite,
			wantParams: map[string]string{
				ParamPath: "/path/to/database.db",
			},
			wantErr: false,
		},
		{
			name:    "empty DSN",
			dsn:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			settings, err := NewSettingsFromDSN(tt.dsn)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if settings.Driver != tt.wantDriver {
				t.Errorf("Driver = %s, want %s", settings.Driver, tt.wantDriver)
			}

			for key, wantValue := range tt.wantParams {
				gotValue := settings.Params[key]
				if gotValue != wantValue {
					t.Errorf("Params[%s] = %s, want %s", key, gotValue, wantValue)
				}
			}
		})
	}
}

// TestFileStorage tests the file storage implementation
func TestFileStorage(t *testing.T) {
	t.Parallel()
	// Create a temporary JSON file for testing
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_data.json")

	testData := map[string]interface{}{
		"key1": "value1",
		"key2": map[string]interface{}{
			"nested": "value2",
		},
		"key3": []interface{}{"item1", "item2"},
	}

	jsonData, err := json.Marshal(testData)
	if err != nil {
		t.Fatalf("failed to marshal test data: %v", err)
	}

	if err := os.WriteFile(testFile, jsonData, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Create file storage
	settings := Settings{
		Driver: DriverFile,
		Params: map[string]string{
			ParamPath: testFile,
		},
	}

	storage, err := NewFileStorage(settings)
	if err != nil {
		t.Fatalf("failed to create file storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	t.Run("Get existing key", func(t *testing.T) {
		data, err := storage.Get(ctx, "key1")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatalf("failed to unmarshal value: %v", err)
		}

		if value != "value1" {
			t.Errorf("value = %s, want value1", value)
		}
	})

	t.Run("Get nested key", func(t *testing.T) {
		data, err := storage.Get(ctx, "key2")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		var value map[string]interface{}
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatalf("failed to unmarshal value: %v", err)
		}

		if value["nested"] != "value2" {
			t.Errorf("nested value = %v, want value2", value["nested"])
		}
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		_, err := storage.Get(ctx, "nonexistent")
		if err != ErrKeyNotFound {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("GetByID existing key", func(t *testing.T) {
		data, err := storage.GetByID(ctx, "key1")
		if err != nil {
			t.Fatalf("GetByID failed: %v", err)
		}

		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatalf("failed to unmarshal value: %v", err)
		}

		if value != "value1" {
			t.Errorf("value = %s, want value1", value)
		}
	})

	t.Run("YAML file loading", func(t *testing.T) {
		yamlFile := filepath.Join(tmpDir, "origins.yml")
		yamlData := map[string]interface{}{
			"host.example.com": map[string]interface{}{
				"id":       "yaml-origin",
				"hostname": "host.example.com",
				"action":   map[string]interface{}{"type": "proxy", "url": "https://example.com"},
			},
		}
		ymlBytes, err := yaml.Marshal(yamlData)
		if err != nil {
			t.Fatalf("failed to marshal YAML: %v", err)
		}
		if err := os.WriteFile(yamlFile, ymlBytes, 0644); err != nil {
			t.Fatalf("failed to write YAML file: %v", err)
		}
		yamlStorage, err := NewFileStorage(Settings{
			Driver: DriverFile,
			Params: map[string]string{ParamPath: yamlFile},
		})
		if err != nil {
			t.Fatalf("failed to create file storage for YAML: %v", err)
		}
		defer yamlStorage.Close()
		data, err := yamlStorage.Get(ctx, "host.example.com")
		if err != nil {
			t.Fatalf("Get from YAML storage failed: %v", err)
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("failed to unmarshal stored config: %v", err)
		}
		if cfg["id"] != "yaml-origin" || cfg["hostname"] != "host.example.com" {
			t.Errorf("unexpected config: %v", cfg)
		}
	})

	t.Run("Put returns read-only error", func(t *testing.T) {
		err := storage.Put(ctx, "newkey", []byte("value"))
		if err != ErrReadOnly {
			t.Errorf("expected ErrReadOnly, got %v", err)
		}
	})

	t.Run("Delete returns read-only error", func(t *testing.T) {
		err := storage.Delete(ctx, "key1")
		if err != ErrReadOnly {
			t.Errorf("expected ErrReadOnly, got %v", err)
		}
	})

	t.Run("DeleteByPrefix returns read-only error", func(t *testing.T) {
		err := storage.DeleteByPrefix(ctx, "key")
		if err != ErrReadOnly {
			t.Errorf("expected ErrReadOnly, got %v", err)
		}
	})

	t.Run("Driver returns correct driver name", func(t *testing.T) {
		if storage.Driver() != DriverFile {
			t.Errorf("Driver() = %s, want %s", storage.Driver(), DriverFile)
		}
	})

	t.Run("Context cancellation", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := storage.Get(cancelCtx, "key1")
		if err == nil {
			t.Error("expected error for cancelled context")
		}
	})
}

// TestFileStorageErrors tests error cases
func TestFileStorageErrors(t *testing.T) {
	t.Parallel()
	t.Run("missing file path", func(t *testing.T) {
		t.Parallel()
		settings := Settings{
			Driver: DriverFile,
			Params: map[string]string{},
		}

		_, err := NewFileStorage(settings)
		if err == nil {
			t.Error("expected error for missing file path")
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		t.Parallel()
		settings := Settings{
			Driver: DriverFile,
			Params: map[string]string{
				ParamPath: "/nonexistent/path/to/file.json",
			},
		}

		_, err := NewFileStorage(settings)
		if err == nil {
			t.Error("expected error for non-existent file")
		}
	})

	t.Run("invalid JSON file", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "invalid.json")

		if err := os.WriteFile(testFile, []byte("not valid json"), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		settings := Settings{
			Driver: DriverFile,
			Params: map[string]string{
				ParamPath: testFile,
			},
		}

		_, err := NewFileStorage(settings)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

// TestRegisterAndNewStorage tests driver registration and storage creation
func TestRegisterAndNewStorage(t *testing.T) {
	t.Run("available drivers", func(t *testing.T) {
		drivers := AvailableDrivers()
		if len(drivers) == 0 {
			t.Error("expected at least one registered driver")
		}

		// File driver should be registered via init()
		found := false
		for _, d := range drivers {
			if d == DriverFile {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected file driver to be registered")
		}
	})

	t.Run("unsupported driver", func(t *testing.T) {
		settings := Settings{
			Driver: "unsupported_driver",
			Params: map[string]string{},
		}

		_, err := NewStorage(settings)
		if err != ErrUnsupportedDriver {
			t.Errorf("expected ErrUnsupportedDriver, got %v", err)
		}
	})

	t.Run("NewStorage with file driver", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.json")

		if err := os.WriteFile(testFile, []byte(`{"key": "value"}`), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		settings := Settings{
			Driver: DriverFile,
			Params: map[string]string{
				ParamPath: testFile,
			},
		}

		storage, err := NewStorage(settings)
		if err != nil {
			t.Fatalf("NewStorage failed: %v", err)
		}
		defer storage.Close()

		data, err := storage.Get(context.Background(), "key")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if value != "value" {
			t.Errorf("value = %s, want value", value)
		}
	})

	t.Run("NewStorageFromDSN", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.json")

		if err := os.WriteFile(testFile, []byte(`{"key": "value"}`), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		storage, err := NewStorageFromDSN("file://" + testFile)
		if err != nil {
			t.Fatalf("NewStorageFromDSN failed: %v", err)
		}
		defer storage.Close()

		if storage.Driver() != DriverFile {
			t.Errorf("Driver() = %s, want %s", storage.Driver(), DriverFile)
		}
	})
}

// TestRegisterDriver tests driver registration
func TestRegisterDriver(t *testing.T) {
	// Register a mock driver
	mockDriverName := "mock_test_driver"
	mockCalled := false

	Register(mockDriverName, func(settings Settings) (Storage, error) {
		mockCalled = true
		return nil, ErrInvalidConfiguration
	})

	// Verify it's in available drivers
	drivers := AvailableDrivers()
	found := false
	for _, d := range drivers {
		if d == mockDriverName {
			found = true
			break
		}
	}
	if !found {
		t.Error("mock driver should be in available drivers")
	}

	// Try to create storage with mock driver
	_, _ = NewStorage(Settings{Driver: mockDriverName})

	if !mockCalled {
		t.Error("mock driver constructor should have been called")
	}
}

// BenchmarkFileStorageGet benchmarks file storage Get operation
func BenchmarkFileStorageGet(b *testing.B) {
	b.ReportAllocs()
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "bench.json")

	// Create test data with multiple keys
	testData := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		testData["key"+string(rune('0'+i%10))+string(rune('0'+i/10))] = "value"
	}

	jsonData, _ := json.Marshal(testData)
	os.WriteFile(testFile, jsonData, 0644)

	storage, err := NewFileStorage(Settings{
		Driver: DriverFile,
		Params: map[string]string{ParamPath: testFile},
	})
	if err != nil {
		b.Fatalf("failed to create storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = storage.Get(ctx, "key00")
	}
}
