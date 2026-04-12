// config_version.go implements versioned configuration snapshots with rollback support.
package ai

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"
)

// ConfigVersion represents a snapshot of a configuration at a point in time.
type ConfigVersion struct {
	ID        string          `json:"id"`
	ConfigID  string          `json:"config_id"`
	Version   int             `json:"version"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
	CreatedBy string          `json:"created_by,omitempty"`
	Comment   string          `json:"comment,omitempty"`
	Active    bool            `json:"active"`
}

// ConfigVersionStore manages config version history.
type ConfigVersionStore interface {
	SaveVersion(ctx context.Context, v *ConfigVersion) error
	GetVersion(ctx context.Context, configID string, version int) (*ConfigVersion, error)
	GetActive(ctx context.Context, configID string) (*ConfigVersion, error)
	ListVersions(ctx context.Context, configID string, limit int) ([]*ConfigVersion, error)
	SetActive(ctx context.Context, configID string, version int) error
}

// MemoryConfigVersionStore is an in-memory implementation of ConfigVersionStore.
type MemoryConfigVersionStore struct {
	mu       sync.RWMutex
	versions map[string][]*ConfigVersion // configID -> versions (sorted by version desc)
	active   map[string]int              // configID -> active version number
	pinned   map[string]map[string]int   // configID -> keyID -> pinned version
}

// NewMemoryConfigVersionStore creates a new in-memory config version store.
func NewMemoryConfigVersionStore() *MemoryConfigVersionStore {
	return &MemoryConfigVersionStore{
		versions: make(map[string][]*ConfigVersion),
		active:   make(map[string]int),
		pinned:   make(map[string]map[string]int),
	}
}

// SaveVersion stores a new config version.
func (s *MemoryConfigVersionStore) SaveVersion(_ context.Context, v *ConfigVersion) error {
	if v == nil {
		return fmt.Errorf("config version: cannot save nil version")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	versions := s.versions[v.ConfigID]
	// Insert at the beginning (sorted desc by version).
	s.versions[v.ConfigID] = append([]*ConfigVersion{v}, versions...)

	if v.Active {
		s.active[v.ConfigID] = v.Version
	}

	return nil
}

// GetVersion returns a specific version of a config.
func (s *MemoryConfigVersionStore) GetVersion(_ context.Context, configID string, version int) (*ConfigVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, v := range s.versions[configID] {
		if v.Version == version {
			cp := *v
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("config version: version %d not found for config %q", version, configID)
}

// GetActive returns the currently active version for a config.
func (s *MemoryConfigVersionStore) GetActive(_ context.Context, configID string) (*ConfigVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	activeVersion, ok := s.active[configID]
	if !ok {
		return nil, fmt.Errorf("config version: no active version for config %q", configID)
	}

	for _, v := range s.versions[configID] {
		if v.Version == activeVersion {
			cp := *v
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("config version: active version %d not found for config %q", activeVersion, configID)
}

// ListVersions returns up to limit versions for a config, sorted by version desc.
func (s *MemoryConfigVersionStore) ListVersions(_ context.Context, configID string, limit int) ([]*ConfigVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions := s.versions[configID]
	if len(versions) == 0 {
		return nil, nil
	}

	count := len(versions)
	if limit > 0 && limit < count {
		count = limit
	}

	result := make([]*ConfigVersion, count)
	for i := 0; i < count; i++ {
		cp := *versions[i]
		result[i] = &cp
	}
	return result, nil
}

// SetActive sets the active version for a config.
func (s *MemoryConfigVersionStore) SetActive(_ context.Context, configID string, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for _, v := range s.versions[configID] {
		if v.Version == version {
			v.Active = true
			found = true
		} else {
			v.Active = false
		}
	}

	if !found {
		return fmt.Errorf("config version: version %d not found for config %q", version, configID)
	}

	s.active[configID] = version
	return nil
}

// SetPinnedVersion pins a specific config version to an API key.
func (s *MemoryConfigVersionStore) SetPinnedVersion(configID string, version int, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify the version exists.
	found := false
	for _, v := range s.versions[configID] {
		if v.Version == version {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("config version: version %d not found for config %q", version, configID)
	}

	if s.pinned[configID] == nil {
		s.pinned[configID] = make(map[string]int)
	}
	s.pinned[configID][keyID] = version
	return nil
}

// GetPinnedVersion returns the pinned version for a key, or 0 if not pinned.
func (s *MemoryConfigVersionStore) GetPinnedVersion(configID string, keyID string) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if pins, ok := s.pinned[configID]; ok {
		if v, found := pins[keyID]; found {
			return v, true
		}
	}
	return 0, false
}

// ConfigVersionManager provides high-level version management.
type ConfigVersionManager struct {
	store ConfigVersionStore
}

// NewConfigVersionManager creates a new config version manager.
func NewConfigVersionManager(store ConfigVersionStore) *ConfigVersionManager {
	return &ConfigVersionManager{store: store}
}

// CreateVersion saves a new version, auto-increments the version number, and sets it as active.
func (m *ConfigVersionManager) CreateVersion(ctx context.Context, configID string, data json.RawMessage, createdBy, comment string) (*ConfigVersion, error) {
	if configID == "" {
		return nil, fmt.Errorf("config version: configID is required")
	}

	// Determine the next version number.
	existing, err := m.store.ListVersions(ctx, configID, 1)
	if err != nil {
		return nil, fmt.Errorf("config version: failed to list versions: %w", err)
	}

	nextVersion := 1
	if len(existing) > 0 {
		nextVersion = existing[0].Version + 1
	}

	v := &ConfigVersion{
		ID:        uuid.New().String(),
		ConfigID:  configID,
		Version:   nextVersion,
		Data:      data,
		CreatedAt: time.Now(),
		CreatedBy: createdBy,
		Comment:   comment,
		Active:    true,
	}

	if err := m.store.SaveVersion(ctx, v); err != nil {
		return nil, fmt.Errorf("config version: failed to save version: %w", err)
	}

	// Set as active (also clears Active flag on previous versions).
	if err := m.store.SetActive(ctx, configID, nextVersion); err != nil {
		return nil, fmt.Errorf("config version: failed to set active: %w", err)
	}

	return v, nil
}

// Rollback sets a previous version as active.
func (m *ConfigVersionManager) Rollback(ctx context.Context, configID string, version int) (*ConfigVersion, error) {
	v, err := m.store.GetVersion(ctx, configID, version)
	if err != nil {
		return nil, fmt.Errorf("config version: rollback failed: %w", err)
	}

	if err := m.store.SetActive(ctx, configID, version); err != nil {
		return nil, fmt.Errorf("config version: rollback set active failed: %w", err)
	}

	v.Active = true
	return v, nil
}

// GetActive returns the currently active config version.
func (m *ConfigVersionManager) GetActive(ctx context.Context, configID string) (*ConfigVersion, error) {
	return m.store.GetActive(ctx, configID)
}

// Diff returns the JSON differences between two versions as a map of changed fields.
// Each entry contains "v1" and "v2" values showing what changed.
func (m *ConfigVersionManager) Diff(ctx context.Context, configID string, v1, v2 int) (map[string]any, error) {
	ver1, err := m.store.GetVersion(ctx, configID, v1)
	if err != nil {
		return nil, fmt.Errorf("config version: diff failed for v%d: %w", v1, err)
	}
	ver2, err := m.store.GetVersion(ctx, configID, v2)
	if err != nil {
		return nil, fmt.Errorf("config version: diff failed for v%d: %w", v2, err)
	}

	var map1, map2 map[string]any
	if err := json.Unmarshal(ver1.Data, &map1); err != nil {
		return nil, fmt.Errorf("config version: failed to parse v%d data: %w", v1, err)
	}
	if err := json.Unmarshal(ver2.Data, &map2); err != nil {
		return nil, fmt.Errorf("config version: failed to parse v%d data: %w", v2, err)
	}

	diff := make(map[string]any)

	// Collect all keys from both maps.
	allKeys := make(map[string]struct{})
	for k := range map1 {
		allKeys[k] = struct{}{}
	}
	for k := range map2 {
		allKeys[k] = struct{}{}
	}

	// Sort keys for deterministic output.
	keys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val1, ok1 := map1[k]
		val2, ok2 := map2[k]

		if !ok1 {
			diff[k] = map[string]any{"v1": nil, "v2": val2}
		} else if !ok2 {
			diff[k] = map[string]any{"v1": val1, "v2": nil}
		} else {
			// Compare by serializing to JSON for deep equality.
			b1, _ := json.Marshal(val1)
			b2, _ := json.Marshal(val2)
			if string(b1) != string(b2) {
				diff[k] = map[string]any{"v1": val1, "v2": val2}
			}
		}
	}

	return diff, nil
}

// History returns version history for a config.
func (m *ConfigVersionManager) History(ctx context.Context, configID string, limit int) ([]*ConfigVersion, error) {
	return m.store.ListVersions(ctx, configID, limit)
}

// PinToKey associates a specific config version with an API key.
// This requires the underlying store to support pinning (MemoryConfigVersionStore does).
func (m *ConfigVersionManager) PinToKey(ctx context.Context, configID string, version int, keyID string) error {
	// Verify the version exists.
	if _, err := m.store.GetVersion(ctx, configID, version); err != nil {
		return fmt.Errorf("config version: pin failed: %w", err)
	}

	// Use type assertion for stores that support pinning.
	type pinner interface {
		SetPinnedVersion(configID string, version int, keyID string) error
	}

	if p, ok := m.store.(pinner); ok {
		return p.SetPinnedVersion(configID, version, keyID)
	}

	return fmt.Errorf("config version: store does not support key pinning")
}
