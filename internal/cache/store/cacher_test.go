package cacher

import (
	"bytes"
	"context"
	"testing"
)

// NOTE: Drivers (file, memory, wrapper, etc.) are registered via init() functions
// in their respective packages and imported by the main package. This test file
// tests the cacher package directly without importing drivers to avoid import cycles.

func TestNewManager(t *testing.T) {
	tests := []struct {
		name        string
		settings    Settings
		expectError bool
	}{
		{
			name: "valid noop driver",
			settings: Settings{
				Driver: "noop",
			},
			expectError: false,
		},
		{
			name: "unsupported driver",
			settings: Settings{
				Driver: "unsupported",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewCacher(tt.settings)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if manager == nil {
				t.Errorf("expected manager but got nil")
				return
			}

			// Test that the manager implements the interface
			ctx := context.Background()

			// Test basic operations
			err = manager.Put(ctx, "test-type", "test-key", bytes.NewReader([]byte("test-value")))
			if err != nil {
				t.Errorf("Put failed: %v", err)
			}

			_, err = manager.Get(ctx, "test-type", "test-key")
			if err != nil && err != ErrNotFound {
				t.Errorf("Get failed: %v", err)
			}

			// Test increment
			count, err := manager.Increment(ctx, "test-type", "counter", 1)
			if err != nil {
				t.Errorf("Increment failed: %v", err)
			}
			if count < 1 {
				t.Errorf("Expected count >= 1, got %d", count)
			}

			// Test cleanup
			err = manager.Close()
			if err != nil {
				t.Errorf("Close failed: %v", err)
			}
		})
	}
}

func TestAvailableDrivers(t *testing.T) {
	drivers := AvailableDrivers()

	// Should include at least noop driver (always registered)
	// Other drivers (memory, file, redis, etc.) are registered via init() in their packages
	// and imported by the main package, but not in this test to avoid import cycles
	expectedDrivers := []string{"noop"}

	for _, expected := range expectedDrivers {
		found := false
		for _, driver := range drivers {
			if driver == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected driver %s not found in available drivers: %v", expected, drivers)
		}
	}

	// At minimum, we should have at least one driver
	if len(drivers) == 0 {
		t.Error("no drivers available")
	}
}

func TestParseMemorySize(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    int64
		expectError bool
	}{
		{
			name:     "1TB parses correctly",
			input:    "1TB",
			expected: 1024 * 1024 * 1024 * 1024,
		},
		{
			name:        "999999TB exceeds max and returns error",
			input:       "999999TB",
			expectError: true,
		},
		{
			name:     "empty string returns zero",
			input:    "",
			expected: 0,
		},
		{
			name:     "plain bytes",
			input:    "4096",
			expected: 4096,
		},
		{
			name:     "megabytes",
			input:    "256MB",
			expected: 256 * 1024 * 1024,
		},
		{
			name:        "no number returns error",
			input:       "MB",
			expectError: true,
		},
		{
			name:        "unsupported unit returns error",
			input:       "100PB",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseMemorySize(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for input %q, got result=%d", tt.input, result)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("parseMemorySize(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRegister(t *testing.T) {
	// Test registering a custom driver
	// Register a test driver
	Register("test-driver", func(settings Settings) (Cacher, error) {
		return &noop{}, nil
	})

	// Check that it's available
	drivers := AvailableDrivers()
	found := false
	for _, driver := range drivers {
		if driver == "test-driver" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("test-driver not found in available drivers: %v", drivers)
	}

	// Test that we can create a manager with the test driver
	settings := Settings{
		Driver: "test-driver",
	}

	manager, err := NewCacher(settings)
	if err != nil {
		t.Errorf("failed to create manager with test driver: %v", err)
	}
	if manager == nil {
		t.Errorf("expected manager but got nil")
	}

	// Clean up
	manager.Close()
}
