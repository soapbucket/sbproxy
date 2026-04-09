package wasm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testValidWASM returns a minimal valid WASM module that exports sb_on_request and sb_malloc.
// Contains two functions:
//   - sb_malloc(i32) -> i32  (returns 0)
//   - sb_on_request() -> i32 (returns 0)
func testValidWASM() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
		0x01, 0x0a, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f, // type section
		0x03, 0x03, 0x02, 0x00, 0x01, // function section
		0x07, 0x1d, 0x02, // export section header
		0x09, 0x73, 0x62, 0x5f, 0x6d, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x00, 0x00, // sb_malloc
		0x0d, 0x73, 0x62, 0x5f, 0x6f, 0x6e, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x00, 0x01, // sb_on_request
		0x0a, 0x0b, 0x02, // code section header
		0x04, 0x00, 0x41, 0x00, 0x0b, // sb_malloc body
		0x04, 0x00, 0x41, 0x00, 0x0b, // sb_on_request body
	}
}

func TestFileBackend_StoreAndLoad(t *testing.T) {
	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	meta := &ModuleMetadata{
		Name:    "test-module",
		Version: "v1.0.0",
		SHA256:  "abc123",
		Size:    42,
	}
	data := []byte("fake-wasm-data")

	ctx := context.Background()
	if err := fb.Store(ctx, "ws-1", meta, data); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, gotMeta, err := fb.Load(ctx, "ws-1", "test-module", "v1.0.0")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if string(got) != string(data) {
		t.Errorf("data mismatch: got %q, want %q", got, data)
	}
	if gotMeta.Name != "test-module" {
		t.Errorf("meta.Name: got %q, want %q", gotMeta.Name, "test-module")
	}
	if gotMeta.Version != "v1.0.0" {
		t.Errorf("meta.Version: got %q, want %q", gotMeta.Version, "v1.0.0")
	}
	if gotMeta.SHA256 != "abc123" {
		t.Errorf("meta.SHA256: got %q, want %q", gotMeta.SHA256, "abc123")
	}
}

func TestFileBackend_LoadNotFound(t *testing.T) {
	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	ctx := context.Background()
	_, _, err = fb.Load(ctx, "ws-1", "nonexistent", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for nonexistent module")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestFileBackend_ListVersions(t *testing.T) {
	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	ctx := context.Background()
	meta := &ModuleMetadata{Name: "mymod", Size: 4}

	// Store three versions.
	for _, v := range []string{"v1.0.0", "v2.0.0", "v1.1.0"} {
		meta.Version = v
		if err := fb.Store(ctx, "ws-1", meta, []byte("data")); err != nil {
			t.Fatalf("Store %s: %v", v, err)
		}
	}

	versions, err := fb.ListVersions(ctx, "ws-1", "mymod")
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}

	if len(versions) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(versions))
	}

	// Verify sorted order.
	expected := []string{"v1.0.0", "v1.1.0", "v2.0.0"}
	for i, v := range expected {
		if versions[i] != v {
			t.Errorf("versions[%d]: got %q, want %q", i, versions[i], v)
		}
	}
}

func TestFileBackend_ListVersions_NotFound(t *testing.T) {
	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	versions, err := fb.ListVersions(context.Background(), "ws-1", "nomod")
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if versions != nil {
		t.Errorf("expected nil versions for nonexistent module, got %v", versions)
	}
}

func TestFileBackend_Delete(t *testing.T) {
	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	ctx := context.Background()
	meta := &ModuleMetadata{Name: "mymod", Version: "v1.0.0", Size: 4}
	if err := fb.Store(ctx, "ws-1", meta, []byte("data")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	if err := fb.Delete(ctx, "ws-1", "mymod", "v1.0.0"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify module is gone.
	_, _, err = fb.Load(ctx, "ws-1", "mymod", "v1.0.0")
	if err == nil {
		t.Error("expected error loading deleted module")
	}

	// Verify parent dir is cleaned up.
	nameDir := filepath.Join(dir, "ws-1", "mymod")
	if _, err := os.Stat(nameDir); !os.IsNotExist(err) {
		t.Error("expected parent directory to be cleaned up")
	}
}

func TestFileBackend_WorkspaceIsolation(t *testing.T) {
	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	ctx := context.Background()
	meta := &ModuleMetadata{Name: "shared-mod", Version: "v1.0.0", Size: 4}

	if err := fb.Store(ctx, "ws-1", meta, []byte("ws1-data")); err != nil {
		t.Fatalf("Store ws-1: %v", err)
	}
	if err := fb.Store(ctx, "ws-2", meta, []byte("ws2-data")); err != nil {
		t.Fatalf("Store ws-2: %v", err)
	}

	// Each workspace gets its own data.
	data1, _, err := fb.Load(ctx, "ws-1", "shared-mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Load ws-1: %v", err)
	}
	data2, _, err := fb.Load(ctx, "ws-2", "shared-mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Load ws-2: %v", err)
	}

	if string(data1) != "ws1-data" {
		t.Errorf("ws-1 data: got %q, want %q", data1, "ws1-data")
	}
	if string(data2) != "ws2-data" {
		t.Errorf("ws-2 data: got %q, want %q", data2, "ws2-data")
	}
}

func TestNewFileBackend_EmptyDir(t *testing.T) {
	_, err := NewFileBackend("")
	if err == nil {
		t.Error("expected error for empty base_dir")
	}
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	ctx := context.Background()

	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	reg := NewRegistry(fb, rt, RegistryConfig{})

	wasmBytes := testValidWASM()
	hash := computeSHA256(wasmBytes)

	err = reg.Register(ctx, "ws-1", &ModuleRegistration{
		Name:       "test-plugin",
		Version:    "v1.0.0",
		Source:     wasmBytes,
		UploadedBy: "test-user",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rm, err := reg.Get(ctx, "ws-1", "test-plugin", "v1.0.0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if rm.Name != "test-plugin" {
		t.Errorf("Name: got %q, want %q", rm.Name, "test-plugin")
	}
	if rm.Version != "v1.0.0" {
		t.Errorf("Version: got %q, want %q", rm.Version, "v1.0.0")
	}
	if rm.SHA256 != hash {
		t.Errorf("SHA256: got %q, want %q", rm.SHA256, hash)
	}
	if rm.Compiled == nil {
		t.Error("Compiled module should not be nil")
	}
	if rm.UploadedBy != "test-user" {
		t.Errorf("UploadedBy: got %q, want %q", rm.UploadedBy, "test-user")
	}
	if rm.Size != int64(len(wasmBytes)) {
		t.Errorf("Size: got %d, want %d", rm.Size, len(wasmBytes))
	}
}

func TestRegistry_CompilationCache(t *testing.T) {
	ctx := context.Background()

	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	reg := NewRegistry(fb, rt, RegistryConfig{})

	wasmBytes := testValidWASM()

	// Register same binary as two versions.
	for _, v := range []string{"v1.0.0", "v2.0.0"} {
		err = reg.Register(ctx, "ws-1", &ModuleRegistration{
			Name:    "test-plugin",
			Version: v,
			Source:  wasmBytes,
		})
		if err != nil {
			t.Fatalf("Register %s: %v", v, err)
		}
	}

	// Both versions should return the same compiled module (cached by hash).
	rm1, err := reg.Get(ctx, "ws-1", "test-plugin", "v1.0.0")
	if err != nil {
		t.Fatalf("Get v1: %v", err)
	}
	rm2, err := reg.Get(ctx, "ws-1", "test-plugin", "v2.0.0")
	if err != nil {
		t.Fatalf("Get v2: %v", err)
	}

	if rm1.SHA256 != rm2.SHA256 {
		t.Errorf("identical modules should have same SHA256: %s vs %s", rm1.SHA256, rm2.SHA256)
	}
}

func TestRegistry_ListVersions(t *testing.T) {
	ctx := context.Background()

	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	reg := NewRegistry(fb, rt, RegistryConfig{})

	wasmBytes := testValidWASM()
	for _, v := range []string{"v1.0.0", "v2.0.0"} {
		err = reg.Register(ctx, "ws-1", &ModuleRegistration{
			Name:    "test-plugin",
			Version: v,
			Source:  wasmBytes,
		})
		if err != nil {
			t.Fatalf("Register %s: %v", v, err)
		}
	}

	versions, err := reg.ListVersions(ctx, "ws-1", "test-plugin")
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
}

func TestRegistry_Delete(t *testing.T) {
	ctx := context.Background()

	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	reg := NewRegistry(fb, rt, RegistryConfig{})

	wasmBytes := testValidWASM()
	err = reg.Register(ctx, "ws-1", &ModuleRegistration{
		Name:    "test-plugin",
		Version: "v1.0.0",
		Source:  wasmBytes,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := reg.Delete(ctx, "ws-1", "test-plugin", "v1.0.0"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = reg.Get(ctx, "ws-1", "test-plugin", "v1.0.0")
	if err == nil {
		t.Error("expected error getting deleted module")
	}
}

func TestRegistry_SHA256Mismatch(t *testing.T) {
	ctx := context.Background()

	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	reg := NewRegistry(fb, rt, RegistryConfig{})

	err = reg.Register(ctx, "ws-1", &ModuleRegistration{
		Name:    "test-plugin",
		Version: "v1.0.0",
		Source:  testValidWASM(),
		SHA256:  "wrong-hash",
	})
	if err == nil {
		t.Error("expected error for SHA-256 mismatch")
	}
	if !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("expected SHA-256 mismatch error, got: %v", err)
	}
}

func TestRegistry_ModuleTooLarge(t *testing.T) {
	ctx := context.Background()

	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	// Set max size to 1MB.
	reg := NewRegistry(fb, rt, RegistryConfig{MaxModuleSizeMB: 1})

	// Create data larger than 1MB.
	bigData := make([]byte, 2*1024*1024)

	err = reg.Register(ctx, "ws-1", &ModuleRegistration{
		Name:    "big-plugin",
		Version: "v1.0.0",
		Source:  bigData,
	})
	if err == nil {
		t.Error("expected error for oversized module")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Errorf("expected size error, got: %v", err)
	}
}

func TestRegistry_NilSource(t *testing.T) {
	ctx := context.Background()

	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	reg := NewRegistry(fb, rt, RegistryConfig{})

	err = reg.Register(ctx, "ws-1", &ModuleRegistration{
		Name:    "test-plugin",
		Version: "v1.0.0",
		Source:  nil,
	})
	if err == nil {
		t.Error("expected error for nil source")
	}
}

func TestRegistry_ValidationErrors(t *testing.T) {
	ctx := context.Background()

	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer rt.Close(ctx)

	dir := t.TempDir()
	fb, err := NewFileBackend(dir)
	if err != nil {
		t.Fatalf("NewFileBackend: %v", err)
	}

	reg := NewRegistry(fb, rt, RegistryConfig{})

	tests := []struct {
		name      string
		workspace string
		modName   string
		version   string
		wantErr   string
	}{
		{"empty workspace", "", "mod", "v1", "workspace ID is required"},
		{"empty module name", "ws-1", "", "v1", "module name is required"},
		{"empty version", "ws-1", "mod", "", "version is required"},
	}

	for _, tt := range tests {
		t.Run("Get_"+tt.name, func(t *testing.T) {
			_, err := reg.Get(ctx, tt.workspace, tt.modName, tt.version)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected %q in error, got: %v", tt.wantErr, err)
			}
		})
		t.Run("Delete_"+tt.name, func(t *testing.T) {
			err := reg.Delete(ctx, tt.workspace, tt.modName, tt.version)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected %q in error, got: %v", tt.wantErr, err)
			}
		})
	}

	// Register-specific validations.
	t.Run("Register_nil_registration", func(t *testing.T) {
		err := reg.Register(ctx, "ws-1", nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("Register_empty_name", func(t *testing.T) {
		err := reg.Register(ctx, "ws-1", &ModuleRegistration{Version: "v1", Source: []byte{1}})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "module name is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Register_empty_version", func(t *testing.T) {
		err := reg.Register(ctx, "ws-1", &ModuleRegistration{Name: "mod", Source: []byte{1}})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "version is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("ListVersions_empty_workspace", func(t *testing.T) {
		_, err := reg.ListVersions(ctx, "", "mod")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("ListVersions_empty_name", func(t *testing.T) {
		_, err := reg.ListVersions(ctx, "ws-1", "")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestComputeSHA256(t *testing.T) {
	hash := computeSHA256([]byte("hello"))
	// Known SHA-256 of "hello".
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash != expected {
		t.Errorf("got %s, want %s", hash, expected)
	}
}
