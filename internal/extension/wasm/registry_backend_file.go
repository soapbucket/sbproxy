package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/goccy/go-json"
)

// FileBackend stores WASM modules on the local filesystem.
// Directory layout: {baseDir}/{workspaceID}/{moduleName}/{version}/module.wasm + metadata.json
type FileBackend struct {
	baseDir string
}

// NewFileBackend creates a file-based storage backend rooted at baseDir.
func NewFileBackend(baseDir string) (*FileBackend, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("registry: base_dir is required for file backend")
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("registry: create base dir: %w", err)
	}
	return &FileBackend{baseDir: baseDir}, nil
}

func (f *FileBackend) modulePath(workspaceID, name, version string) string {
	return filepath.Join(f.baseDir, workspaceID, name, version)
}

func (f *FileBackend) Load(_ context.Context, workspaceID, name, version string) ([]byte, *ModuleMetadata, error) {
	dir := f.modulePath(workspaceID, name, version)

	data, err := os.ReadFile(filepath.Join(dir, "module.wasm"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("registry: module %s:%s not found in workspace %s", name, version, workspaceID)
		}
		return nil, nil, fmt.Errorf("registry: read module: %w", err)
	}

	metaBytes, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("registry: read metadata: %w", err)
	}

	var meta ModuleMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, nil, fmt.Errorf("registry: parse metadata: %w", err)
	}

	return data, &meta, nil
}

func (f *FileBackend) Store(_ context.Context, workspaceID string, meta *ModuleMetadata, data []byte) error {
	dir := f.modulePath(workspaceID, meta.Name, meta.Version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("registry: create module dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "module.wasm"), data, 0o644); err != nil {
		return fmt.Errorf("registry: write module: %w", err)
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("registry: marshal metadata: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), metaBytes, 0o644); err != nil {
		return fmt.Errorf("registry: write metadata: %w", err)
	}

	return nil
}

func (f *FileBackend) ListVersions(_ context.Context, workspaceID, name string) ([]string, error) {
	dir := filepath.Join(f.baseDir, workspaceID, name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("registry: list versions: %w", err)
	}

	var versions []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Only include directories that contain a module.wasm file.
		wasmPath := filepath.Join(dir, e.Name(), "module.wasm")
		if _, err := os.Stat(wasmPath); err == nil {
			versions = append(versions, e.Name())
		}
	}
	sort.Strings(versions)
	return versions, nil
}

func (f *FileBackend) Delete(_ context.Context, workspaceID, name, version string) error {
	dir := f.modulePath(workspaceID, name, version)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("registry: delete module: %w", err)
	}

	// Clean up empty parent directories.
	nameDir := filepath.Join(f.baseDir, workspaceID, name)
	entries, _ := os.ReadDir(nameDir)
	if len(entries) == 0 {
		os.Remove(nameDir)
	}

	return nil
}
