package config

import (
	"strings"
	"testing"
)

func TestLoadStorageConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid s3 config",
			input: `{
				"type": "storage",
				"kind": "s3",
				"bucket": "my-bucket",
				"region": "us-east-1",
				"key": "AKIAIOSFODNN7EXAMPLE",
				"secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
			}`,
			expectError: false,
		},
		{
			name: "valid azure config",
			input: `{
				"type": "storage",
				"kind": "azure",
				"bucket": "my-container",
				"account": "myaccount",
				"key": "mykey"
			}`,
			expectError: false,
		},
		{
			name: "valid google config",
			input: `{
				"type": "storage",
				"kind": "google",
				"bucket": "my-bucket",
				"project_id": "my-project"
			}`,
			expectError: false,
		},
		{
			name: "valid b2 config",
			input: `{
				"type": "storage",
				"kind": "b2",
				"bucket": "my-bucket",
				"key": "my-key-id",
				"secret": "my-app-key"
			}`,
			expectError: false,
		},
		{
			name: "valid swift config",
			input: `{
				"type": "storage",
				"kind": "swift",
				"bucket": "my-container",
				"tenant_name": "my-tenant",
				"tenant_auth_url": "https://auth.example.com",
				"key": "username",
				"secret": "password"
			}`,
			expectError: false,
		},
		{
			name: "missing kind",
			input: `{
				"type": "storage",
				"bucket": "my-bucket"
			}`,
			expectError: true,
			errorMsg:    "kind is required",
		},
		{
			name: "missing bucket",
			input: `{
				"type": "storage",
				"kind": "s3"
			}`,
			expectError: true,
			errorMsg:    "bucket is required",
		},
		{
			name: "invalid kind",
			input: `{
				"type": "storage",
				"kind": "invalid",
				"bucket": "my-bucket"
			}`,
			expectError: true,
			errorMsg:    "invalid storage kind",
		},
		{
			name: "invalid json",
			input: `{
				"type": "storage",
				"kind": 12345,
				"bucket": "my-bucket"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadStorageConfig([]byte(tt.input))
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("expected config but got nil")
			}

			if cfg.GetType() != TypeStorage {
				t.Errorf("expected type %s, got %s", TypeStorage, cfg.GetType())
			}

			// Test transport is set
			if cfg.Transport() == nil {
				t.Error("expected transport to be set")
			}
		})
	}
}

func TestBuildStorageSettings(t *testing.T) {
	tests := []struct {
		name     string
		config   *StorageConfig
		expected map[string]string
	}{
		{
			name: "s3 with all fields",
			config: &StorageConfig{
				Kind:   "s3",
				Bucket: "my-bucket",
				Region: "us-east-1",
				Key:    "AKIAIOSFODNN7EXAMPLE",
				Secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			expected: map[string]string{
				"bucket": "my-bucket",
				"region": "us-east-1",
				"key":    "AKIAIOSFODNN7EXAMPLE",
				"secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
		},
		{
			name: "google with project id",
			config: &StorageConfig{
				Kind:      "google",
				Bucket:    "my-bucket",
				ProjectID: "my-project-123",
			},
			expected: map[string]string{
				"bucket":    "my-bucket",
				"projectId": "my-project-123",
			},
		},
		{
			name: "azure with account",
			config: &StorageConfig{
				Kind:    "azure",
				Bucket:  "my-container",
				Account: "myaccount",
				Key:     "mykey",
			},
			expected: map[string]string{
				"bucket":  "my-container",
				"account": "myaccount",
				"key":     "mykey",
			},
		},
		{
			name: "swift with tenant",
			config: &StorageConfig{
				Kind:          "swift",
				Bucket:        "my-container",
				TenantName:    "my-tenant",
				TenantAuthURL: "https://auth.example.com",
				Key:           "username",
				Secret:        "password",
			},
			expected: map[string]string{
				"bucket":        "my-container",
				"tenant":        "my-tenant",
				"tenantAuthURL": "https://auth.example.com",
				"key":           "username",
				"secret":        "password",
			},
		},
		{
			name: "minimal config",
			config: &StorageConfig{
				Kind:   "s3",
				Bucket: "my-bucket",
			},
			expected: map[string]string{
				"bucket": "my-bucket",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := buildStorageSettings(tt.config)

			for key, expectedValue := range tt.expected {
				actualValue, ok := settings[key]
				if !ok {
					t.Errorf("expected setting %q not found", key)
					continue
				}
				if actualValue != expectedValue {
					t.Errorf("expected setting %s=%q, got %q", key, expectedValue, actualValue)
				}
			}

			// Verify no extra keys
			for key := range settings {
				if _, ok := tt.expected[key]; !ok {
					t.Errorf("unexpected setting %q=%v", key, settings[key])
				}
			}
		})
	}
}

func TestValidStorageKinds(t *testing.T) {
	validKinds := []string{"s3", "azure", "google", "swift", "b2"}
	invalidKinds := []string{"dropbox", "gdrive", "onedrive", "ftp", ""}

	for _, kind := range validKinds {
		if !validStorageKinds[kind] {
			t.Errorf("expected %q to be a valid storage kind", kind)
		}
	}

	for _, kind := range invalidKinds {
		if validStorageKinds[kind] {
			t.Errorf("expected %q to be an invalid storage kind", kind)
		}
	}
}

