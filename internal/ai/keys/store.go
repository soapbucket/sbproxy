package keys

import (
	"context"
	"fmt"
	"sync"
)

// Store defines the interface for virtual key storage.
type Store interface {
	Create(ctx context.Context, key *VirtualKey) error
	GetByHash(ctx context.Context, hashedKey string) (*VirtualKey, error)
	GetByID(ctx context.Context, id string) (*VirtualKey, error)
	List(ctx context.Context, workspaceID string, opts ListOpts) ([]*VirtualKey, error)
	Update(ctx context.Context, id string, updates map[string]any) error
	Revoke(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

// ErrKeyNotFound is returned when a virtual key is not found.
var ErrKeyNotFound = fmt.Errorf("virtual key not found")

// MemoryStore is an in-memory, thread-safe virtual key store.
type MemoryStore struct {
	mu      sync.RWMutex
	byID    map[string]*VirtualKey
	byHash  map[string]*VirtualKey
}

// NewMemoryStore creates a new in-memory virtual key store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID:   make(map[string]*VirtualKey),
		byHash: make(map[string]*VirtualKey),
	}
}

// Create stores a new virtual key.
func (s *MemoryStore) Create(_ context.Context, key *VirtualKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[key.ID]; exists {
		return fmt.Errorf("key with ID %s already exists", key.ID)
	}
	if _, exists := s.byHash[key.HashedKey]; exists {
		return fmt.Errorf("key with this hash already exists")
	}

	cp := *key
	s.byID[key.ID] = &cp
	s.byHash[key.HashedKey] = &cp
	return nil
}

// GetByHash retrieves a virtual key by its hashed value.
func (s *MemoryStore) GetByHash(_ context.Context, hashedKey string) (*VirtualKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	vk, ok := s.byHash[hashedKey]
	if !ok {
		return nil, ErrKeyNotFound
	}
	cp := *vk
	return &cp, nil
}

// GetByID retrieves a virtual key by its ID.
func (s *MemoryStore) GetByID(_ context.Context, id string) (*VirtualKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	vk, ok := s.byID[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	cp := *vk
	return &cp, nil
}

// List returns virtual keys for a workspace, filtered by opts.
func (s *MemoryStore) List(_ context.Context, workspaceID string, opts ListOpts) ([]*VirtualKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*VirtualKey
	for _, vk := range s.byID {
		if vk.WorkspaceID != workspaceID {
			continue
		}
		if opts.Status != "" && vk.Status != opts.Status {
			continue
		}
		cp := *vk
		result = append(result, &cp)
	}

	// Apply offset
	if opts.Offset > 0 {
		if opts.Offset >= len(result) {
			return nil, nil
		}
		result = result[opts.Offset:]
	}

	// Apply limit
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}

	return result, nil
}

// Update modifies fields on an existing virtual key.
func (s *MemoryStore) Update(_ context.Context, id string, updates map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	vk, ok := s.byID[id]
	if !ok {
		return ErrKeyNotFound
	}

	for field, value := range updates {
		switch field {
		case "name":
			if v, ok := value.(string); ok {
				vk.Name = v
			}
		case "status":
			if v, ok := value.(string); ok {
				vk.Status = v
			}
		case "allowed_models":
			if v, ok := value.([]string); ok {
				vk.AllowedModels = v
			}
		case "blocked_models":
			if v, ok := value.([]string); ok {
				vk.BlockedModels = v
			}
		case "allowed_providers":
			if v, ok := value.([]string); ok {
				vk.AllowedProviders = v
			}
		case "max_tokens_per_min":
			if v, ok := value.(int); ok {
				vk.MaxTokensPerMin = v
			}
		case "max_requests_per_min":
			if v, ok := value.(int); ok {
				vk.MaxRequestsPerMin = v
			}
		case "max_budget_usd":
			if v, ok := value.(float64); ok {
				vk.MaxBudgetUSD = v
			}
		case "budget_period":
			if v, ok := value.(string); ok {
				vk.BudgetPeriod = v
			}
		case "max_tokens":
			if v, ok := value.(int64); ok {
				vk.MaxTokens = v
			}
		case "token_budget_action":
			if v, ok := value.(string); ok {
				vk.TokenBudgetAction = v
			}
		case "downgrade_map":
			if v, ok := value.(map[string]string); ok {
				vk.DowngradeMap = v
			}
		case "provider_keys":
			if v, ok := value.(map[string]string); ok {
				vk.ProviderKeys = v
			}
		case "metadata":
			if v, ok := value.(map[string]string); ok {
				vk.Metadata = v
			}
		case "role":
			if v, ok := value.(string); ok {
				vk.Role = v
			}
		case "project_id":
			if v, ok := value.(string); ok {
				vk.ProjectID = v
			}
		}
	}

	return nil
}

// Revoke sets a virtual key's status to "revoked".
func (s *MemoryStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	vk, ok := s.byID[id]
	if !ok {
		return ErrKeyNotFound
	}
	vk.Status = "revoked"
	return nil
}

// Delete removes a virtual key from the store.
func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	vk, ok := s.byID[id]
	if !ok {
		return ErrKeyNotFound
	}
	delete(s.byHash, vk.HashedKey)
	delete(s.byID, id)
	return nil
}
