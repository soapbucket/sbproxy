package embedded

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func resetExtract() {
	extractOnce = sync.Once{}
	if extractDir != "" {
		os.RemoveAll(extractDir)
		extractDir = ""
	}
}

func TestVersionParsesCorrectly(t *testing.T) {
	v := Version()

	if v.GeneratedAt == "" {
		t.Fatal("GeneratedAt should not be empty")
	}

	expectedFiles := []string{"ai_providers.yml", "regexes.yml"}
	for _, name := range expectedFiles {
		info, ok := v.Files[name]
		if !ok {
			t.Fatalf("missing file entry: %s", name)
		}
		if info.SHA256 == "" {
			t.Errorf("%s: SHA256 should not be empty", name)
		}
		if len(info.SHA256) != 64 {
			t.Errorf("%s: SHA256 should be 64 hex chars, got %d", name, len(info.SHA256))
		}
		if info.Size <= 0 {
			t.Errorf("%s: Size should be positive, got %d", name, info.Size)
		}
		if info.CompressedSize <= 0 {
			t.Errorf("%s: CompressedSize should be positive, got %d", name, info.CompressedSize)
		}
		if info.CompressedSize >= info.Size {
			t.Errorf("%s: CompressedSize (%d) should be less than Size (%d)", name, info.CompressedSize, info.Size)
		}
		if info.UpdatedAt == "" {
			t.Errorf("%s: UpdatedAt should not be empty", name)
		}
	}
}

func TestEmbeddedFilesDecompress(t *testing.T) {
	files := map[string][]byte{
		"ai_providers.yml": aiProvidersGz,
		"regexes.yml":      regexesGz,
	}

	for name, data := range files {
		t.Run(name, func(t *testing.T) {
			if len(data) == 0 {
				t.Fatalf("embedded data for %s is empty", name)
			}

			dir := t.TempDir()
			if err := extractFile(dir, name, data); err != nil {
				t.Fatalf("failed to decompress %s: %v", name, err)
			}

			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("extracted file not found: %v", err)
			}
			if info.Size() == 0 {
				t.Fatalf("extracted file is empty")
			}

			// Verify size matches version.json metadata.
			if vi, ok := version.Files[name]; ok {
				if info.Size() != vi.Size {
					t.Errorf("extracted size %d does not match version.json size %d", info.Size(), vi.Size)
				}
			}
		})
	}
}

func TestExtractToTempCreatesFiles(t *testing.T) {
	resetExtract()
	t.Cleanup(func() { resetExtract() })

	dir, err := ExtractToTemp()
	if err != nil {
		t.Fatalf("ExtractToTemp failed: %v", err)
	}

	if dir == "" {
		t.Fatal("ExtractToTemp returned empty directory")
	}

	expectedFiles := []string{"ai_providers.yml", "regexes.yml"}
	for _, name := range expectedFiles {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected file %s not found: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
	}
}

func TestExtractToTempIsIdempotent(t *testing.T) {
	resetExtract()
	t.Cleanup(func() { resetExtract() })

	dir1, err := ExtractToTemp()
	if err != nil {
		t.Fatalf("first ExtractToTemp failed: %v", err)
	}

	dir2, err := ExtractToTemp()
	if err != nil {
		t.Fatalf("second ExtractToTemp failed: %v", err)
	}

	if dir1 != dir2 {
		t.Errorf("ExtractToTemp should return same dir, got %s and %s", dir1, dir2)
	}
}

func TestFilePathReturnsEmbeddedWhenNoOverride(t *testing.T) {
	resetExtract()
	t.Cleanup(func() { resetExtract() })

	path := FilePath("ai_providers.yml", "")
	if path == "" {
		t.Fatal("FilePath returned empty string")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file at path does not exist: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("file at path is empty")
	}
}

func TestFilePathReturnsOverrideWhenExists(t *testing.T) {
	resetExtract()
	t.Cleanup(func() { resetExtract() })

	// Create a temporary override file.
	tmpFile := filepath.Join(t.TempDir(), "override.yml")
	if err := os.WriteFile(tmpFile, []byte("override content"), 0644); err != nil {
		t.Fatalf("failed to create override file: %v", err)
	}

	path := FilePath("ai_providers.yml", tmpFile)
	if path != tmpFile {
		t.Errorf("expected override path %s, got %s", tmpFile, path)
	}
}

func TestFilePathFallsBackWhenOverrideMissing(t *testing.T) {
	resetExtract()
	t.Cleanup(func() { resetExtract() })

	path := FilePath("ai_providers.yml", "/nonexistent/path/file.yml")
	if path == "" {
		t.Fatal("FilePath returned empty string")
	}
	if path == "/nonexistent/path/file.yml" {
		t.Fatal("FilePath should not return nonexistent override path")
	}

	// Should be the embedded extracted path.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("fallback file does not exist: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("fallback file is empty")
	}
}
