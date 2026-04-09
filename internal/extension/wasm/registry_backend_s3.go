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

// S3API is the minimal S3 client interface required by the S3 backend.
// This allows use with aws-sdk-go-v2/service/s3.Client or any compatible implementation.
type S3API interface {
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, body io.Reader, contentType string) error
	DeleteObject(ctx context.Context, key string) error
	ListObjects(ctx context.Context, prefix string) ([]string, error)
}

// S3Backend stores WASM modules in an S3-compatible bucket.
// Object layout: {prefix}/{workspaceID}/{moduleName}/{version}/module.wasm + metadata.json
type S3Backend struct {
	client S3API
	prefix string
}

// NewS3Backend creates an S3-based storage backend.
func NewS3Backend(client S3API, prefix string) *S3Backend {
	return &S3Backend{
		client: client,
		prefix: strings.TrimSuffix(prefix, "/"),
	}
}

func (s *S3Backend) keyPath(workspaceID, name, version, file string) string {
	parts := []string{}
	if s.prefix != "" {
		parts = append(parts, s.prefix)
	}
	parts = append(parts, workspaceID, name, version, file)
	return path.Join(parts...)
}

func (s *S3Backend) Load(ctx context.Context, workspaceID, name, version string) ([]byte, *ModuleMetadata, error) {
	wasmKey := s.keyPath(workspaceID, name, version, "module.wasm")
	metaKey := s.keyPath(workspaceID, name, version, "metadata.json")

	wasmReader, err := s.client.GetObject(ctx, wasmKey)
	if err != nil {
		return nil, nil, fmt.Errorf("registry: s3 get module: %w", err)
	}
	defer wasmReader.Close()

	data, err := io.ReadAll(wasmReader)
	if err != nil {
		return nil, nil, fmt.Errorf("registry: s3 read module: %w", err)
	}

	metaReader, err := s.client.GetObject(ctx, metaKey)
	if err != nil {
		return nil, nil, fmt.Errorf("registry: s3 get metadata: %w", err)
	}
	defer metaReader.Close()

	metaBytes, err := io.ReadAll(metaReader)
	if err != nil {
		return nil, nil, fmt.Errorf("registry: s3 read metadata: %w", err)
	}

	var meta ModuleMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, nil, fmt.Errorf("registry: s3 parse metadata: %w", err)
	}

	return data, &meta, nil
}

func (s *S3Backend) Store(ctx context.Context, workspaceID string, meta *ModuleMetadata, data []byte) error {
	wasmKey := s.keyPath(workspaceID, meta.Name, meta.Version, "module.wasm")
	metaKey := s.keyPath(workspaceID, meta.Name, meta.Version, "metadata.json")

	if err := s.client.PutObject(ctx, wasmKey, bytes.NewReader(data), "application/wasm"); err != nil {
		return fmt.Errorf("registry: s3 put module: %w", err)
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("registry: s3 marshal metadata: %w", err)
	}

	if err := s.client.PutObject(ctx, metaKey, bytes.NewReader(metaBytes), "application/json"); err != nil {
		return fmt.Errorf("registry: s3 put metadata: %w", err)
	}

	return nil
}

func (s *S3Backend) ListVersions(ctx context.Context, workspaceID, name string) ([]string, error) {
	prefix := s.keyPath(workspaceID, name, "", "")
	// Ensure prefix ends with separator for listing.
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	keys, err := s.client.ListObjects(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("registry: s3 list: %w", err)
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

func (s *S3Backend) Delete(ctx context.Context, workspaceID, name, version string) error {
	wasmKey := s.keyPath(workspaceID, name, version, "module.wasm")
	metaKey := s.keyPath(workspaceID, name, version, "metadata.json")

	if err := s.client.DeleteObject(ctx, wasmKey); err != nil {
		return fmt.Errorf("registry: s3 delete module: %w", err)
	}

	if err := s.client.DeleteObject(ctx, metaKey); err != nil {
		return fmt.Errorf("registry: s3 delete metadata: %w", err)
	}

	return nil
}
