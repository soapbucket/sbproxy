package wasm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ModuleRegistry manages versioned WASM modules with workspace-scoped access.
type ModuleRegistry interface {
	// Get retrieves a compiled module by name and version.
	Get(ctx context.Context, workspaceID, moduleName, version string) (*RegisteredModule, error)
	// Register uploads a new module version.
	Register(ctx context.Context, workspaceID string, reg *ModuleRegistration) error
	// ListVersions returns available versions for a module.
	ListVersions(ctx context.Context, workspaceID, moduleName string) ([]string, error)
	// Delete removes a module version.
	Delete(ctx context.Context, workspaceID, moduleName, version string) error
}

// RegisteredModule is a compiled WASM module retrieved from the registry.
type RegisteredModule struct {
	Name       string
	Version    string
	SHA256     string
	Compiled   *CompiledModule
	UploadedAt time.Time
	UploadedBy string
	Size       int64
}

// ModuleRegistration is the input for registering a new module.
type ModuleRegistration struct {
	Name       string
	Version    string
	Source     []byte // raw WASM bytes
	SHA256     string // expected hash for verification
	UploadedBy string
}

// RegistryConfig configures the module registry.
type RegistryConfig struct {
	// Type is the backend type: "file", "s3", or "gcs".
	Type string `yaml:"type" json:"type"`

	// File backend settings.
	BaseDir string `yaml:"base_dir" json:"base_dir"`

	// S3 backend settings.
	S3Bucket   string `yaml:"s3_bucket" json:"s3_bucket"`
	S3Region   string `yaml:"s3_region" json:"s3_region"`
	S3Prefix   string `yaml:"s3_prefix" json:"s3_prefix"`
	S3Endpoint string `yaml:"s3_endpoint" json:"s3_endpoint"` // for MinIO/localstack

	// GCS backend settings.
	GCSBucket string `yaml:"gcs_bucket" json:"gcs_bucket"`
	GCSPrefix string `yaml:"gcs_prefix" json:"gcs_prefix"`

	// MaxCacheSizeMB is the maximum compiled module cache size in MB. Default: 256.
	MaxCacheSizeMB int `yaml:"max_cache_size_mb" json:"max_cache_size_mb"`
	// MaxModuleSizeMB is the maximum allowed module binary size in MB. Default: 10.
	MaxModuleSizeMB int `yaml:"max_module_size_mb" json:"max_module_size_mb"`
}

// StorageBackend abstracts the underlying storage for WASM module binaries.
type StorageBackend interface {
	// Load reads a module from storage.
	Load(ctx context.Context, workspaceID, name, version string) ([]byte, *ModuleMetadata, error)
	// Store writes a module to storage.
	Store(ctx context.Context, workspaceID string, meta *ModuleMetadata, data []byte) error
	// ListVersions returns available versions.
	ListVersions(ctx context.Context, workspaceID, name string) ([]string, error)
	// Delete removes a module version.
	Delete(ctx context.Context, workspaceID, name, version string) error
}

// ModuleMetadata is stored alongside the module binary.
type ModuleMetadata struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	UploadedAt time.Time `json:"uploaded_at"`
	UploadedBy string    `json:"uploaded_by"`
}

// registry is the default implementation of ModuleRegistry.
type registry struct {
	mu      sync.RWMutex
	backend StorageBackend
	cache   sync.Map // sha256 -> *RegisteredModule (compiled module cache)
	runtime *Runtime
	config  RegistryConfig
}

// NewRegistry creates a new module registry with the given backend and runtime.
func NewRegistry(backend StorageBackend, rt *Runtime, config RegistryConfig) ModuleRegistry {
	return &registry{
		backend: backend,
		runtime: rt,
		config:  config,
	}
}

func (r *registry) Get(ctx context.Context, workspaceID, moduleName, version string) (*RegisteredModule, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("registry: workspace ID is required")
	}
	if moduleName == "" {
		return nil, fmt.Errorf("registry: module name is required")
	}
	if version == "" {
		return nil, fmt.Errorf("registry: version is required")
	}

	data, meta, err := r.backend.Load(ctx, workspaceID, moduleName, version)
	if err != nil {
		return nil, fmt.Errorf("registry: load %s:%s: %w", moduleName, version, err)
	}

	// Verify integrity.
	if err := VerifyIntegrity(data, meta.SHA256); err != nil {
		return nil, fmt.Errorf("registry: %s:%s: %w", moduleName, version, err)
	}

	hash := computeSHA256(data)

	// Check compilation cache.
	if cached, ok := r.cache.Load(hash); ok {
		return cached.(*RegisteredModule), nil
	}

	// Compile module.
	compiled, err := r.runtime.Compile(ctx, meta.Name, data)
	if err != nil {
		return nil, fmt.Errorf("registry: compile %s:%s: %w", moduleName, version, err)
	}

	rm := &RegisteredModule{
		Name:       meta.Name,
		Version:    meta.Version,
		SHA256:     hash,
		Compiled:   compiled,
		UploadedAt: meta.UploadedAt,
		UploadedBy: meta.UploadedBy,
		Size:       meta.Size,
	}

	// Cache by content hash to deduplicate identical modules across versions/workspaces.
	r.cache.Store(hash, rm)
	return rm, nil
}

func (r *registry) Register(ctx context.Context, workspaceID string, reg *ModuleRegistration) error {
	if workspaceID == "" {
		return fmt.Errorf("registry: workspace ID is required")
	}
	if reg == nil {
		return fmt.Errorf("registry: registration is nil")
	}
	if reg.Name == "" {
		return fmt.Errorf("registry: module name is required")
	}
	if reg.Version == "" {
		return fmt.Errorf("registry: version is required")
	}
	if reg.Source == nil {
		return fmt.Errorf("registry: module source is nil")
	}

	maxSize := r.config.MaxModuleSizeMB
	if maxSize <= 0 {
		maxSize = 10
	}
	if len(reg.Source) > maxSize*1024*1024 {
		return fmt.Errorf("registry: module exceeds max size of %dMB", maxSize)
	}

	// Compute and verify hash.
	hash := computeSHA256(reg.Source)
	if reg.SHA256 != "" && hash != reg.SHA256 {
		return fmt.Errorf("registry: SHA-256 mismatch: expected %s, got %s", reg.SHA256, hash)
	}

	// Verify module compiles.
	compiled, err := r.runtime.Compile(ctx, reg.Name, reg.Source)
	if err != nil {
		return fmt.Errorf("registry: module does not compile: %w", err)
	}

	now := time.Now().UTC()
	meta := &ModuleMetadata{
		Name:       reg.Name,
		Version:    reg.Version,
		SHA256:     hash,
		Size:       int64(len(reg.Source)),
		UploadedAt: now,
		UploadedBy: reg.UploadedBy,
	}

	if err := r.backend.Store(ctx, workspaceID, meta, reg.Source); err != nil {
		return fmt.Errorf("registry: store %s:%s: %w", reg.Name, reg.Version, err)
	}

	// Pre-cache the compiled module.
	rm := &RegisteredModule{
		Name:       meta.Name,
		Version:    meta.Version,
		SHA256:     hash,
		Compiled:   compiled,
		UploadedAt: now,
		UploadedBy: reg.UploadedBy,
		Size:       meta.Size,
	}
	r.cache.Store(hash, rm)

	return nil
}

func (r *registry) ListVersions(ctx context.Context, workspaceID, moduleName string) ([]string, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("registry: workspace ID is required")
	}
	if moduleName == "" {
		return nil, fmt.Errorf("registry: module name is required")
	}
	return r.backend.ListVersions(ctx, workspaceID, moduleName)
}

func (r *registry) Delete(ctx context.Context, workspaceID, moduleName, version string) error {
	if workspaceID == "" {
		return fmt.Errorf("registry: workspace ID is required")
	}
	if moduleName == "" {
		return fmt.Errorf("registry: module name is required")
	}
	if version == "" {
		return fmt.Errorf("registry: version is required")
	}

	// Load first to get hash for cache invalidation.
	_, meta, err := r.backend.Load(ctx, workspaceID, moduleName, version)
	if err == nil && meta != nil {
		r.cache.Delete(meta.SHA256)
	}

	return r.backend.Delete(ctx, workspaceID, moduleName, version)
}

// computeSHA256 returns the hex-encoded SHA-256 hash of data.
func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
