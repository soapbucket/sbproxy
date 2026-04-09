package wasm

import (
	"context"
	"testing"
)

func TestPluginConfig_Validation(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	tests := []struct {
		name    string
		cfg     PluginConfig
		wantErr string
	}{
		{
			name:    "empty name",
			cfg:     PluginConfig{},
			wantErr: "plugin name is required",
		},
		{
			name: "invalid phase",
			cfg: PluginConfig{
				Name:   "test",
				Phase:  "invalid",
				Source: []byte{0x00}, // dummy bytes, will fail later but phase check comes first
			},
			wantErr: "invalid plugin phase",
		},
		{
			name: "no source or path",
			cfg: PluginConfig{
				Name:  "test",
				Phase: PhaseRequest,
			},
			wantErr: "either path or source must be provided",
		},
		{
			name: "non-existent path",
			cfg: PluginConfig{
				Name:  "test",
				Phase: PhaseRequest,
				Path:  "/nonexistent/path/module.wasm",
			},
			wantErr: "failed to read WASM file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rt.LoadPlugin(ctx, tt.cfg)
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantErr != "" {
				if !containsStr(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestPlugin_DefaultPhase(t *testing.T) {
	// Verify that the default phase logic works at the config level
	cfg := PluginConfig{
		Name: "test-plugin",
	}
	if cfg.Phase == "" {
		// The LoadPlugin function applies the default, so Phase "" -> "request"
		// We just verify the constant is correct
		if PhaseRequest != "request" {
			t.Errorf("expected PhaseRequest=%q, got %q", "request", PhaseRequest)
		}
	}
}

func TestPlugin_PhaseConstants(t *testing.T) {
	if PhaseRequest != "request" {
		t.Errorf("expected PhaseRequest=%q, got %q", "request", PhaseRequest)
	}
	if PhaseResponse != "response" {
		t.Errorf("expected PhaseResponse=%q, got %q", "response", PhaseResponse)
	}
}

func TestLoadPlugin_ClosedRuntime(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}

	// Close the runtime first
	rt.Close(ctx)

	_, err = rt.LoadPlugin(ctx, PluginConfig{
		Name:   "test",
		Source: []byte{0x00, 0x61, 0x73, 0x6d}, // WASM magic number (incomplete)
	})
	if err == nil {
		t.Error("expected error loading plugin on closed runtime")
	}
	if !containsStr(err.Error(), "closed") {
		t.Errorf("expected 'closed' in error, got: %v", err)
	}
}

func TestResolveSource_InlineBytes(t *testing.T) {
	src := []byte{0x00, 0x61, 0x73, 0x6d}
	data, err := resolveSource(PluginConfig{Source: src})
	if err != nil {
		t.Fatalf("resolveSource failed: %v", err)
	}
	if len(data) != len(src) {
		t.Errorf("expected %d bytes, got %d", len(src), len(data))
	}
}

func TestResolveSource_NoSourceOrPath(t *testing.T) {
	_, err := resolveSource(PluginConfig{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveFromRegistry_RegistryPrefix(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	// Without registry set, registry: prefix should fail.
	_, err = rt.resolveFromRegistry(ctx, PluginConfig{
		Name: "test",
		Path: "registry:my-mod:v1.0.0",
	})
	if err == nil {
		t.Fatal("expected error when registry is not configured")
	}
	if !containsStr(err.Error(), "no module registry is configured") {
		t.Errorf("unexpected error: %v", err)
	}

	// Invalid format: missing version.
	dir := t.TempDir()
	fb, fbErr := NewFileBackend(dir)
	if fbErr != nil {
		t.Fatalf("NewFileBackend: %v", fbErr)
	}
	reg := NewRegistry(fb, rt, RegistryConfig{})
	rt.SetRegistry(reg)

	_, err = rt.resolveFromRegistry(ctx, PluginConfig{
		Name:        "test",
		Path:        "registry:my-mod",
		WorkspaceID: "ws-1",
	})
	if err == nil {
		t.Fatal("expected error for invalid registry reference")
	}
	if !containsStr(err.Error(), "expected registry:name:version") {
		t.Errorf("unexpected error: %v", err)
	}

	// Missing workspace ID.
	_, err = rt.resolveFromRegistry(ctx, PluginConfig{
		Name: "test",
		Path: "registry:my-mod:v1.0.0",
	})
	if err == nil {
		t.Fatal("expected error for missing workspace_id")
	}
	if !containsStr(err.Error(), "requires a workspace_id") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveFromRegistry_SystemPrefix(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	// Without registry set, system: prefix should fail.
	_, err = rt.resolveFromRegistry(ctx, PluginConfig{
		Name: "test",
		Path: "system:my-mod",
	})
	if err == nil {
		t.Fatal("expected error when registry is not configured")
	}
	if !containsStr(err.Error(), "no module registry is configured") {
		t.Errorf("unexpected error: %v", err)
	}

	// Empty name after prefix.
	dir := t.TempDir()
	fb, fbErr := NewFileBackend(dir)
	if fbErr != nil {
		t.Fatalf("NewFileBackend: %v", fbErr)
	}
	reg := NewRegistry(fb, rt, RegistryConfig{})
	rt.SetRegistry(reg)

	_, err = rt.resolveFromRegistry(ctx, PluginConfig{
		Name: "test",
		Path: "system:",
	})
	if err == nil {
		t.Fatal("expected error for empty system module name")
	}
	if !containsStr(err.Error(), "expected system:name") {
		t.Errorf("unexpected error: %v", err)
	}

	// No versions available.
	_, err = rt.resolveFromRegistry(ctx, PluginConfig{
		Name: "test",
		Path: "system:nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent system module")
	}
	if !containsStr(err.Error(), "no versions found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveFromRegistry_NoPrefix(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	// Regular file paths should return nil, nil.
	rm, err := rt.resolveFromRegistry(ctx, PluginConfig{
		Name: "test",
		Path: "/some/file.wasm",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rm != nil {
		t.Error("expected nil module for non-registry path")
	}

	// Empty path should also return nil, nil.
	rm, err = rt.resolveFromRegistry(ctx, PluginConfig{Name: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rm != nil {
		t.Error("expected nil module for empty path")
	}
}

func TestResolveFromRegistry_SystemLatestVersion(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, fbErr := NewFileBackend(dir)
	if fbErr != nil {
		t.Fatalf("NewFileBackend: %v", fbErr)
	}
	reg := NewRegistry(fb, rt, RegistryConfig{})
	rt.SetRegistry(reg)

	wasmBytes := testValidWASM()

	// Register two versions in the system workspace.
	for _, v := range []string{"v1.0.0", "v2.0.0"} {
		if err := reg.Register(ctx, systemWorkspaceID, &ModuleRegistration{
			Name:    "rate-limiter",
			Version: v,
			Source:  wasmBytes,
		}); err != nil {
			t.Fatalf("Register %s: %v", v, err)
		}
	}

	// system:rate-limiter should resolve to v2.0.0 (latest sorted version).
	rm, err := rt.resolveFromRegistry(ctx, PluginConfig{
		Name: "test",
		Path: "system:rate-limiter",
	})
	if err != nil {
		t.Fatalf("resolveFromRegistry: %v", err)
	}
	if rm == nil {
		t.Fatal("expected non-nil module")
	}
	if rm.Version != "v2.0.0" {
		t.Errorf("expected version v2.0.0, got %s", rm.Version)
	}
}

func TestResolveFromRegistry_RegistryLookup(t *testing.T) {
	ctx := context.Background()
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, fbErr := NewFileBackend(dir)
	if fbErr != nil {
		t.Fatalf("NewFileBackend: %v", fbErr)
	}
	reg := NewRegistry(fb, rt, RegistryConfig{})
	rt.SetRegistry(reg)

	wasmBytes := testValidWASM()
	if err := reg.Register(ctx, "ws-1", &ModuleRegistration{
		Name:    "auth-plugin",
		Version: "v3.1.0",
		Source:  wasmBytes,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	rm, err := rt.resolveFromRegistry(ctx, PluginConfig{
		Name:        "test",
		Path:        "registry:auth-plugin:v3.1.0",
		WorkspaceID: "ws-1",
	})
	if err != nil {
		t.Fatalf("resolveFromRegistry: %v", err)
	}
	if rm == nil {
		t.Fatal("expected non-nil module")
	}
	if rm.Name != "auth-plugin" {
		t.Errorf("expected name auth-plugin, got %s", rm.Name)
	}
	if rm.Version != "v3.1.0" {
		t.Errorf("expected version v3.1.0, got %s", rm.Version)
	}
}

// containsStr checks if s contains substr (avoids importing strings for a test helper).
func containsStr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
