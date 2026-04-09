package identity

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// PermissionStore manages permission groups and access groups.
type PermissionStore interface {
	// Permission Groups
	GetGroup(ctx context.Context, id string) (*PermissionGroup, error)
	ListGroups(ctx context.Context) ([]*PermissionGroup, error)
	SaveGroup(ctx context.Context, group *PermissionGroup) error
	DeleteGroup(ctx context.Context, id string) error

	// Access Groups
	GetAccessGroup(ctx context.Context, id string) (*AccessGroup, error)
	ListAccessGroups(ctx context.Context) ([]*AccessGroup, error)
	SaveAccessGroup(ctx context.Context, group *AccessGroup) error
	DeleteAccessGroup(ctx context.Context, id string) error

	// Membership queries
	GroupsForPrincipal(ctx context.Context, principalID string) ([]*PermissionGroup, error)
}

// MemoryPermissionStore is an in-memory implementation of PermissionStore.
type MemoryPermissionStore struct {
	mu           sync.RWMutex
	groups       map[string]*PermissionGroup
	accessGroups map[string]*AccessGroup
}

// NewMemoryPermissionStore creates a new in-memory permission store.
func NewMemoryPermissionStore() *MemoryPermissionStore {
	return &MemoryPermissionStore{
		groups:       make(map[string]*PermissionGroup),
		accessGroups: make(map[string]*AccessGroup),
	}
}

// GetGroup returns a permission group by ID.
func (s *MemoryPermissionStore) GetGroup(_ context.Context, id string) (*PermissionGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	if !ok {
		return nil, fmt.Errorf("identity: permission group %q not found", id)
	}
	return g, nil
}

// ListGroups returns all permission groups.
func (s *MemoryPermissionStore) ListGroups(_ context.Context) ([]*PermissionGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*PermissionGroup, 0, len(s.groups))
	for _, g := range s.groups {
		result = append(result, g)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result, nil
}

// SaveGroup creates or updates a permission group.
func (s *MemoryPermissionStore) SaveGroup(_ context.Context, group *PermissionGroup) error {
	if group == nil {
		return fmt.Errorf("identity: cannot save nil permission group")
	}
	if group.ID == "" {
		return fmt.Errorf("identity: permission group ID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[group.ID] = group
	return nil
}

// DeleteGroup removes a permission group by ID.
func (s *MemoryPermissionStore) DeleteGroup(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[id]; !ok {
		return fmt.Errorf("identity: permission group %q not found", id)
	}
	delete(s.groups, id)
	return nil
}

// GetAccessGroup returns an access group by ID.
func (s *MemoryPermissionStore) GetAccessGroup(_ context.Context, id string) (*AccessGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ag, ok := s.accessGroups[id]
	if !ok {
		return nil, fmt.Errorf("identity: access group %q not found", id)
	}
	return ag, nil
}

// ListAccessGroups returns all access groups.
func (s *MemoryPermissionStore) ListAccessGroups(_ context.Context) ([]*AccessGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*AccessGroup, 0, len(s.accessGroups))
	for _, ag := range s.accessGroups {
		result = append(result, ag)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result, nil
}

// SaveAccessGroup creates or updates an access group.
func (s *MemoryPermissionStore) SaveAccessGroup(_ context.Context, group *AccessGroup) error {
	if group == nil {
		return fmt.Errorf("identity: cannot save nil access group")
	}
	if group.ID == "" {
		return fmt.Errorf("identity: access group ID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessGroups[group.ID] = group
	return nil
}

// DeleteAccessGroup removes an access group by ID.
func (s *MemoryPermissionStore) DeleteAccessGroup(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accessGroups[id]; !ok {
		return fmt.Errorf("identity: access group %q not found", id)
	}
	delete(s.accessGroups, id)
	return nil
}

// GroupsForPrincipal returns all permission groups that contain the given principal ID.
func (s *MemoryPermissionStore) GroupsForPrincipal(_ context.Context, principalID string) ([]*PermissionGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*PermissionGroup
	for _, g := range s.groups {
		for _, m := range g.Members {
			if m == principalID {
				result = append(result, g)
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result, nil
}

// PermissionResolver resolves effective permissions for a principal.
type PermissionResolver struct {
	store PermissionStore
	cache *PermissionCache // optional, may be nil
}

// NewPermissionResolver creates a new permission resolver.
func NewPermissionResolver(store PermissionStore, cache *PermissionCache) *PermissionResolver {
	return &PermissionResolver{
		store: store,
		cache: cache,
	}
}

// Resolve computes effective permissions by walking:
//  1. Find all groups the principal belongs to
//  2. Collect model grants from each group
//  3. Expand access group references to model lists
//  4. Merge grants: deny takes precedence, limits take most restrictive
//  5. Collect all policy IDs
func (pr *PermissionResolver) Resolve(ctx context.Context, principalID string) (*ResolvedPermissions, error) {
	groups, err := pr.store.GroupsForPrincipal(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("identity: failed to resolve groups for principal %q: %w", principalID, err)
	}

	if len(groups) == 0 {
		return &ResolvedPermissions{
			PrincipalID: principalID,
			ModelLimits: make(map[string]ModelLimit),
		}, nil
	}

	// Collect all grants and metadata from all groups.
	var allGrants []ModelGrant
	var allAccessGroupIDs []string
	groupIDs := make([]string, 0, len(groups))
	policySet := make(map[string]struct{})

	for _, g := range groups {
		groupIDs = append(groupIDs, g.ID)
		allGrants = append(allGrants, g.ModelGrants...)
		allAccessGroupIDs = append(allAccessGroupIDs, g.AccessGroups...)
		for _, pid := range g.Policies {
			policySet[pid] = struct{}{}
		}
	}

	// Expand access groups into allow grants.
	if len(allAccessGroupIDs) > 0 {
		expandedModels, expandErr := pr.ExpandAccessGroups(ctx, allAccessGroupIDs)
		if expandErr != nil {
			return nil, expandErr
		}
		for _, model := range expandedModels {
			allGrants = append(allGrants, ModelGrant{
				Model:      model,
				Permission: "allow",
			})
		}
	}

	// Merge all grants.
	allowed, denied, limits := MergeGrants(allGrants)

	// Collect policies.
	policies := make([]string, 0, len(policySet))
	for pid := range policySet {
		policies = append(policies, pid)
	}
	sort.Strings(policies)

	return &ResolvedPermissions{
		PrincipalID:   principalID,
		AllowedModels: allowed,
		DeniedModels:  denied,
		ModelLimits:   limits,
		Groups:        groupIDs,
		Policies:      policies,
	}, nil
}

// ExpandAccessGroups resolves access group references to model lists.
func (pr *PermissionResolver) ExpandAccessGroups(ctx context.Context, groupIDs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var models []string

	for _, id := range groupIDs {
		ag, err := pr.store.GetAccessGroup(ctx, id)
		if err != nil {
			// Skip missing access groups rather than failing the whole resolution.
			continue
		}
		for _, m := range ag.Models {
			if _, ok := seen[m]; !ok {
				seen[m] = struct{}{}
				models = append(models, m)
			}
		}
	}

	sort.Strings(models)
	return models, nil
}
