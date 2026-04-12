package config

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// All action types are registered via pkg/plugin through their
	// respective internal/modules/action/* packages. Tests that need
	// actions import the modules via modules_test.go blank imports,
	// which trigger init() registration into the plugin registry.
	SetRegistry(DefaultRegistry())
	os.Exit(m.Run())
}
