package telemetry

import (
	"path/filepath"
	"testing"
)

func TestShouldBind(t *testing.T) {
	if !ShouldBind(Config{BindPort: 8888}) {
		t.Fatalf("expected bind when port is set")
	}
	if !ShouldBind(Config{BindAddress: "/tmp/telemetry.sock"}) {
		t.Fatalf("expected bind when absolute unix socket path is set")
	}
	if ShouldBind(Config{BindAddress: "127.0.0.1", BindPort: 0}) {
		t.Fatalf("expected no bind when no port and non-absolute address")
	}
}

func TestCreateDirPathIfMissing(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "nested", "telemetry.sock")

	if err := createDirPathIfMissing(target, 0o755); err != nil {
		t.Fatalf("createDirPathIfMissing failed: %v", err)
	}
	if err := createDirPathIfMissing(target, 0o755); err != nil {
		t.Fatalf("createDirPathIfMissing should be idempotent: %v", err)
	}
}
