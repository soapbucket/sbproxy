package config

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Set up the global Registry from legacy init()-populated maps.
	// This ensures tests continue to work as implementations move to sub-packages.
	SetRegistry(DefaultRegistry())
	os.Exit(m.Run())
}
