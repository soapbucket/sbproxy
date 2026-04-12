// embedded.go provides access to embedded static assets such as version info and AI provider data.
package embedded

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

//go:embed version.json
var versionJSON []byte

//go:embed data/ai_providers.yml.gz
var aiProvidersGz []byte

//go:embed data/regexes.yml.gz
var regexesGz []byte

// VersionInfo holds metadata about embedded data files.
type VersionInfo struct {
	GeneratedAt string              `json:"generated_at"`
	Files       map[string]FileInfo `json:"files"`
}

// FileInfo holds metadata about a single embedded file.
type FileInfo struct {
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	CompressedSize int64  `json:"compressed_size"`
	UpdatedAt      string `json:"updated_at"`
}

var (
	version     VersionInfo
	extractDir  string
	extractOnce sync.Once
)

func init() {
	if err := json.Unmarshal(versionJSON, &version); err != nil {
		slog.Error("failed to parse embedded version info", "error", err)
	}
}

// Version returns the embedded data version info.
func Version() VersionInfo {
	return version
}

// ExtractToTemp extracts all embedded data files to a temp directory.
// Returns the directory path. Files are decompressed from gzip.
// The caller should call Cleanup() when done (typically at shutdown).
func ExtractToTemp() (string, error) {
	var err error
	extractOnce.Do(func() {
		extractDir, err = os.MkdirTemp("", "sbproxy-data-*")
		if err != nil {
			return
		}

		files := map[string][]byte{
			"ai_providers.yml": aiProvidersGz,
			"regexes.yml":      regexesGz,
		}
		// geoipCountryGz is optional: it may be nil when the binary is built without
		// a bundled database. Users can provide their own MMDB via config.
		if len(geoipCountryGz) > 0 {
			files["geoip_country.mmdb"] = geoipCountryGz
		}

		for name, data := range files {
			if extractErr := extractFile(extractDir, name, data); extractErr != nil {
				err = fmt.Errorf("extract %s: %w", name, extractErr)
				return
			}
		}
	})
	return extractDir, err
}

func extractFile(dir, name string, gzData []byte) error {
	gr, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		return err
	}
	defer gr.Close()

	outPath := filepath.Join(dir, name)
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, gr); err != nil {
		return err
	}
	return nil
}

// FilePath returns the path to an extracted embedded file.
// If an override path is provided and the file exists, returns the override instead.
// Logs which source was used.
func FilePath(name, overridePath string) string {
	if overridePath != "" {
		if _, err := os.Stat(overridePath); err == nil {
			hash := fileHash(overridePath)
			slog.Info("using external data file", "file", name, "path", overridePath, "sha256", hash)
			return overridePath
		}
		slog.Warn("external data file not found, falling back to embedded", "file", name, "path", overridePath)
	}

	dir, err := ExtractToTemp()
	if err != nil {
		slog.Error("failed to extract embedded data", "error", err)
		return ""
	}

	path := filepath.Join(dir, name)
	if info, ok := version.Files[name]; ok {
		slog.Info("using embedded data file", "file", name, "sha256", info.SHA256, "updated_at", info.UpdatedAt)
	}
	return path
}

func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Cleanup removes the temp directory with extracted files.
func Cleanup() {
	if extractDir != "" {
		os.RemoveAll(extractDir)
	}
}
