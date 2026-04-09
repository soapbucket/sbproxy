package wasm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/goccy/go-json"
)

// GCSAPI is the minimal GCS client interface required by the GCS backend.
// This allows use with cloud.google.com/go/storage.Client or any compatible implementation.
type GCSAPI interface {
	Read(ctx context.Context, key string) (io.ReadCloser, error)
	Write(ctx context.Context, key string, body io.Reader, contentType string) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// GCSBackend stores WASM modules in a Google Cloud Storage bucket.
// Object layout: {prefix}/{workspaceID}/{moduleName}/{version}/module.wasm + metadata.json
type GCSBackend struct {
	client GCSAPI
	prefix string
}

// NewGCSBackend creates a GCS-based storage backend.
func NewGCSBackend(client GCSAPI, prefix string) *GCSBackend {
	return &GCSBackend{
		client: client,
		prefix: strings.TrimSuffix(prefix, "/"),
	}
}

func (g *GCSBackend) keyPath(workspaceID, name, version, file string) string {
	parts := []string{}
	if g.prefix != "" {
		parts = append(parts, g.prefix)
	}
	parts = append(parts, workspaceID, name, version, file)
	return path.Join(parts...)
}

func (g *GCSBackend) Load(ctx context.Context, workspaceID, name, version string) ([]byte, *ModuleMetadata, error) {
	wasmKey := g.keyPath(workspaceID, name, version, "module.wasm")
	metaKey := g.keyPath(workspaceID, name, version, "metadata.json")

	wasmReader, err := g.client.Read(ctx, wasmKey)
	if err != nil {
		return nil, nil, fmt.Errorf("registry: gcs get module: %w", err)
	}
	defer wasmReader.Close()

	data, err := io.ReadAll(wasmReader)
	if err != nil {
		return nil, nil, fmt.Errorf("registry: gcs read module: %w", err)
	}

	metaReader, err := g.client.Read(ctx, metaKey)
	if err != nil {
		return nil, nil, fmt.Errorf("registry: gcs get metadata: %w", err)
	}
	defer metaReader.Close()

	metaBytes, err := io.ReadAll(metaReader)
	if err != nil {
		return nil, nil, fmt.Errorf("registry: gcs read metadata: %w", err)
	}

	var meta ModuleMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, nil, fmt.Errorf("registry: gcs parse metadata: %w", err)
	}

	return data, &meta, nil
}

func (g *GCSBackend) Store(ctx context.Context, workspaceID string, meta *ModuleMetadata, data []byte) error {
	wasmKey := g.keyPath(workspaceID, meta.Name, meta.Version, "module.wasm")
	metaKey := g.keyPath(workspaceID, meta.Name, meta.Version, "metadata.json")

	if err := g.client.Write(ctx, wasmKey, bytes.NewReader(data), "application/wasm"); err != nil {
		return fmt.Errorf("registry: gcs put module: %w", err)
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("registry: gcs marshal metadata: %w", err)
	}

	if err := g.client.Write(ctx, metaKey, bytes.NewReader(metaBytes), "application/json"); err != nil {
		return fmt.Errorf("registry: gcs put metadata: %w", err)
	}

	return nil
}

func (g *GCSBackend) ListVersions(ctx context.Context, workspaceID, name string) ([]string, error) {
	prefix := g.keyPath(workspaceID, name, "", "")
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	keys, err := g.client.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("registry: gcs list: %w", err)
	}

	// Extract unique version directories from keys like {prefix}/{version}/module.wasm
	versionSet := make(map[string]struct{})
	for _, key := range keys {
		rel := strings.TrimPrefix(key, prefix)
		parts := strings.SplitN(rel, "/", 2)
		if len(parts) >= 2 && parts[0] != "" {
			versionSet[parts[0]] = struct{}{}
		}
	}

	versions := make([]string, 0, len(versionSet))
	for v := range versionSet {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	return versions, nil
}

func (g *GCSBackend) Delete(ctx context.Context, workspaceID, name, version string) error {
	wasmKey := g.keyPath(workspaceID, name, version, "module.wasm")
	metaKey := g.keyPath(workspaceID, name, version, "metadata.json")

	if err := g.client.Delete(ctx, wasmKey); err != nil {
		return fmt.Errorf("registry: gcs delete module: %w", err)
	}

	if err := g.client.Delete(ctx, metaKey); err != nil {
		return fmt.Errorf("registry: gcs delete metadata: %w", err)
	}

	return nil
}
