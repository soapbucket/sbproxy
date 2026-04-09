package prompts

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// PromptStore defines the interface for prompt template storage with version history.
type PromptStore interface {
	Create(ctx context.Context, t *PromptTemplate) error
	Get(ctx context.Context, id string) (*PromptTemplate, error)
	GetByName(ctx context.Context, workspaceID, name string) (*PromptTemplate, error)
	GetByLabel(ctx context.Context, workspaceID, name, label string) (*PromptTemplate, error)
	List(ctx context.Context, workspaceID string, limit, offset int) ([]*PromptTemplate, error)
	Update(ctx context.Context, t *PromptTemplate) error
	Delete(ctx context.Context, id string) error
	ListVersions(ctx context.Context, id string) ([]*PromptVersion, error)
	GetVersion(ctx context.Context, id string, version int) (*PromptTemplate, error)
	Rollback(ctx context.Context, id string, version int) error
	SetLabel(ctx context.Context, id string, label string, version int) error
}

// templateRecord holds the current template plus its full version history.
type templateRecord struct {
	current  *PromptTemplate
	versions []*PromptVersion
}

// MemoryPromptStore is an in-memory implementation of PromptStore.
type MemoryPromptStore struct {
	records map[string]*templateRecord
	mu      sync.RWMutex
}

// NewMemoryPromptStore creates a new in-memory prompt store.
func NewMemoryPromptStore() *MemoryPromptStore {
	return &MemoryPromptStore{
		records: make(map[string]*templateRecord),
	}
}

// Create adds a new prompt template to the store.
func (s *MemoryPromptStore) Create(_ context.Context, t *PromptTemplate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[t.ID]; ok {
		return fmt.Errorf("prompt template already exists: %s", t.ID)
	}
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	if t.Version == 0 {
		t.Version = 1
	}
	if t.Labels == nil {
		t.Labels = make(map[string]string)
	}
	cp := copyTemplate(t)
	rec := &templateRecord{
		current: cp,
		versions: []*PromptVersion{
			{
				Version:   cp.Version,
				Template:  copyTemplate(cp),
				CreatedAt: cp.CreatedAt,
				CreatedBy: cp.CreatedBy,
			},
		},
	}
	s.records[t.ID] = rec
	return nil
}

// Get returns a prompt template by ID (current version).
func (s *MemoryPromptStore) Get(_ context.Context, id string) (*PromptTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[id]
	if !ok {
		return nil, fmt.Errorf("prompt template not found: %s", id)
	}
	return copyTemplate(rec.current), nil
}

// GetByName returns a prompt template by workspace and name (current version).
func (s *MemoryPromptStore) GetByName(_ context.Context, workspaceID, name string) (*PromptTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rec := range s.records {
		if rec.current.WorkspaceID == workspaceID && rec.current.Name == name {
			return copyTemplate(rec.current), nil
		}
	}
	return nil, fmt.Errorf("prompt template not found: workspace=%s name=%s", workspaceID, name)
}

// GetByLabel returns the template at a specific labeled version.
func (s *MemoryPromptStore) GetByLabel(_ context.Context, workspaceID, name, label string) (*PromptTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rec := range s.records {
		if rec.current.WorkspaceID != workspaceID || rec.current.Name != name {
			continue
		}
		versionStr, ok := rec.current.Labels[label]
		if !ok {
			return nil, fmt.Errorf("label %q not found for prompt %s", label, rec.current.ID)
		}
		// Find the version in history.
		for _, pv := range rec.versions {
			if fmt.Sprintf("%d", pv.Version) == versionStr {
				return copyTemplate(pv.Template), nil
			}
		}
		return nil, fmt.Errorf("version %s not found for label %q on prompt %s", versionStr, label, rec.current.ID)
	}
	return nil, fmt.Errorf("prompt template not found: workspace=%s name=%s", workspaceID, name)
}

// List returns prompt templates for a workspace with pagination.
func (s *MemoryPromptStore) List(_ context.Context, workspaceID string, limit, offset int) ([]*PromptTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*PromptTemplate
	for _, rec := range s.records {
		if workspaceID == "" || rec.current.WorkspaceID == workspaceID {
			filtered = append(filtered, rec.current)
		}
	}

	// Sort by name for deterministic ordering.
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Name < filtered[j].Name
	})

	// Apply pagination.
	if offset >= len(filtered) {
		return nil, nil
	}
	filtered = filtered[offset:]
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}

	result := make([]*PromptTemplate, len(filtered))
	for i, t := range filtered {
		result[i] = copyTemplate(t)
	}
	return result, nil
}

// Update creates a new version of an existing prompt template.
func (s *MemoryPromptStore) Update(_ context.Context, t *PromptTemplate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[t.ID]
	if !ok {
		return fmt.Errorf("prompt template not found: %s", t.ID)
	}
	now := time.Now()
	newVersion := rec.current.Version + 1
	t.Version = newVersion
	t.CreatedAt = rec.current.CreatedAt
	t.UpdatedAt = now
	// Preserve workspace ID if not set.
	if t.WorkspaceID == "" {
		t.WorkspaceID = rec.current.WorkspaceID
	}
	// Preserve name if not set.
	if t.Name == "" {
		t.Name = rec.current.Name
	}
	// Preserve labels from current.
	if t.Labels == nil {
		t.Labels = make(map[string]string)
	}
	for k, v := range rec.current.Labels {
		if _, exists := t.Labels[k]; !exists {
			t.Labels[k] = v
		}
	}
	cp := copyTemplate(t)
	rec.current = cp
	rec.versions = append(rec.versions, &PromptVersion{
		Version:   newVersion,
		Template:  copyTemplate(cp),
		CreatedAt: now,
		CreatedBy: t.CreatedBy,
	})
	return nil
}

// Delete removes a prompt template from the store.
func (s *MemoryPromptStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; !ok {
		return fmt.Errorf("prompt template not found: %s", id)
	}
	delete(s.records, id)
	return nil
}

// ListVersions returns the version history for a prompt template.
func (s *MemoryPromptStore) ListVersions(_ context.Context, id string) ([]*PromptVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[id]
	if !ok {
		return nil, fmt.Errorf("prompt template not found: %s", id)
	}
	result := make([]*PromptVersion, len(rec.versions))
	for i, v := range rec.versions {
		result[i] = &PromptVersion{
			Version:   v.Version,
			Template:  copyTemplate(v.Template),
			CreatedAt: v.CreatedAt,
			CreatedBy: v.CreatedBy,
		}
	}
	return result, nil
}

// GetVersion returns the template at a specific version number.
func (s *MemoryPromptStore) GetVersion(_ context.Context, id string, version int) (*PromptTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[id]
	if !ok {
		return nil, fmt.Errorf("prompt template not found: %s", id)
	}
	for _, v := range rec.versions {
		if v.Version == version {
			return copyTemplate(v.Template), nil
		}
	}
	return nil, fmt.Errorf("version %d not found for prompt template %s", version, id)
}

// Rollback creates a new version by copying the content from the target version.
func (s *MemoryPromptStore) Rollback(_ context.Context, id string, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return fmt.Errorf("prompt template not found: %s", id)
	}
	var target *PromptVersion
	for _, v := range rec.versions {
		if v.Version == version {
			target = v
			break
		}
	}
	if target == nil {
		return fmt.Errorf("version %d not found for prompt template %s", version, id)
	}
	now := time.Now()
	newVersion := rec.current.Version + 1
	rolled := copyTemplate(target.Template)
	rolled.Version = newVersion
	rolled.UpdatedAt = now
	rolled.Labels = copyLabels(rec.current.Labels)
	rec.current = rolled
	rec.versions = append(rec.versions, &PromptVersion{
		Version:   newVersion,
		Template:  copyTemplate(rolled),
		CreatedAt: now,
		CreatedBy: rolled.CreatedBy,
	})
	return nil
}

// SetLabel assigns a label (e.g. "production") to a specific version number.
func (s *MemoryPromptStore) SetLabel(_ context.Context, id string, label string, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return fmt.Errorf("prompt template not found: %s", id)
	}
	// Verify the version exists.
	found := false
	for _, v := range rec.versions {
		if v.Version == version {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("version %d not found for prompt template %s", version, id)
	}
	if rec.current.Labels == nil {
		rec.current.Labels = make(map[string]string)
	}
	rec.current.Labels[label] = fmt.Sprintf("%d", version)
	return nil
}

// copyTemplate creates a deep copy of a PromptTemplate.
func copyTemplate(t *PromptTemplate) *PromptTemplate {
	if t == nil {
		return nil
	}
	cp := *t
	if len(t.Messages) > 0 {
		cp.Messages = make([]PromptMessage, len(t.Messages))
		copy(cp.Messages, t.Messages)
	}
	if len(t.Variables) > 0 {
		cp.Variables = make([]VariableDef, len(t.Variables))
		copy(cp.Variables, t.Variables)
	}
	cp.Labels = copyLabels(t.Labels)
	return &cp
}

// copyLabels creates a copy of a labels map.
func copyLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return make(map[string]string)
	}
	cp := make(map[string]string, len(labels))
	for k, v := range labels {
		cp[k] = v
	}
	return cp
}

// Store defines the legacy interface for prompt storage.
// Deprecated: Use PromptStore instead.
type Store interface {
	Get(ctx context.Context, id string) (*Prompt, error)
	GetVersion(ctx context.Context, id string, version int) (*LegacyVersion, error)
	List(ctx context.Context) ([]*Prompt, error)
	Create(ctx context.Context, prompt *Prompt) error
	AddVersion(ctx context.Context, id string, version *LegacyVersion) error
	SetActiveVersion(ctx context.Context, id string, version int) error
	Delete(ctx context.Context, id string) error
}

// MemoryStore is an in-memory implementation of the legacy Store interface.
type MemoryStore struct {
	prompts map[string]*Prompt
	mu      sync.RWMutex
}

// NewMemoryStore creates a new in-memory legacy prompt store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		prompts: make(map[string]*Prompt),
	}
}

// Get returns a prompt by ID.
func (s *MemoryStore) Get(_ context.Context, id string) (*Prompt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.prompts[id]
	if !ok {
		return nil, fmt.Errorf("prompt not found: %s", id)
	}
	cp := *p
	cp.Versions = make([]LegacyVersion, len(p.Versions))
	copy(cp.Versions, p.Versions)
	return &cp, nil
}

// GetVersion returns a specific version of a prompt.
func (s *MemoryStore) GetVersion(_ context.Context, id string, version int) (*LegacyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.prompts[id]
	if !ok {
		return nil, fmt.Errorf("prompt not found: %s", id)
	}
	for _, v := range p.Versions {
		if v.Version == version {
			cp := v
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("version %d not found for prompt %s", version, id)
}

// List returns all prompts.
func (s *MemoryStore) List(_ context.Context) ([]*Prompt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Prompt, 0, len(s.prompts))
	for _, p := range s.prompts {
		cp := *p
		cp.Versions = make([]LegacyVersion, len(p.Versions))
		copy(cp.Versions, p.Versions)
		result = append(result, &cp)
	}
	return result, nil
}

// Create adds a new prompt to the store.
func (s *MemoryStore) Create(_ context.Context, prompt *Prompt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.prompts[prompt.ID]; ok {
		return fmt.Errorf("prompt already exists: %s", prompt.ID)
	}
	now := time.Now()
	prompt.CreatedAt = now
	prompt.UpdatedAt = now
	if len(prompt.Versions) > 0 {
		for i := range prompt.Versions {
			if prompt.Versions[i].CreatedAt.IsZero() {
				prompt.Versions[i].CreatedAt = now
			}
		}
		if prompt.ActiveVersion == 0 {
			prompt.ActiveVersion = prompt.Versions[0].Version
		}
	}
	cp := *prompt
	cp.Versions = make([]LegacyVersion, len(prompt.Versions))
	copy(cp.Versions, prompt.Versions)
	s.prompts[prompt.ID] = &cp
	return nil
}

// AddVersion adds a new version to an existing prompt.
func (s *MemoryStore) AddVersion(_ context.Context, id string, version *LegacyVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.prompts[id]
	if !ok {
		return fmt.Errorf("prompt not found: %s", id)
	}
	for _, v := range p.Versions {
		if v.Version == version.Version {
			return fmt.Errorf("version %d already exists for prompt %s", version.Version, id)
		}
	}
	if version.CreatedAt.IsZero() {
		version.CreatedAt = time.Now()
	}
	p.Versions = append(p.Versions, *version)
	p.UpdatedAt = time.Now()
	return nil
}

// SetActiveVersion sets the active version for a prompt.
func (s *MemoryStore) SetActiveVersion(_ context.Context, id string, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.prompts[id]
	if !ok {
		return fmt.Errorf("prompt not found: %s", id)
	}
	found := false
	for _, v := range p.Versions {
		if v.Version == version {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("version %d not found for prompt %s", version, id)
	}
	p.ActiveVersion = version
	p.UpdatedAt = time.Now()
	return nil
}

// Delete removes a prompt from the store.
func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.prompts[id]; !ok {
		return fmt.Errorf("prompt not found: %s", id)
	}
	delete(s.prompts, id)
	return nil
}
