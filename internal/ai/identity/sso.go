package identity

import (
	"context"
	"fmt"
	"sync"
)

// SSOGroupMapping maps an IdP group name to a permission group within a workspace.
type SSOGroupMapping struct {
	IDPGroupName      string `json:"idp_group_name"`
	PermissionGroupID string `json:"permission_group_id"`
	WorkspaceID       string `json:"workspace_id"`
}

// SSOConfig holds the SSO group sync configuration for a workspace.
type SSOConfig struct {
	WorkspaceID    string            `json:"workspace_id"`
	Mappings       []SSOGroupMapping `json:"mappings"`
	AutoProvision  bool              `json:"auto_provision"`
	DefaultGroupID string            `json:"default_group_id,omitempty"`
}

// SSOSyncResult describes the outcome of a group sync operation.
type SSOSyncResult struct {
	Added           []string `json:"added"`
	Removed         []string `json:"removed"`
	Preserved       []string `json:"preserved"`
	AutoProvisioned bool     `json:"auto_provisioned"`
}

// SSOGroupSyncer manages SSO group-to-permission-group mappings per workspace.
type SSOGroupSyncer struct {
	configs map[string]*SSOConfig // workspaceID -> config
	mu      sync.RWMutex
}

// NewSSOGroupSyncer creates a new SSOGroupSyncer.
func NewSSOGroupSyncer() *SSOGroupSyncer {
	return &SSOGroupSyncer{
		configs: make(map[string]*SSOConfig),
	}
}

// SetConfig registers or updates the SSO configuration for a workspace.
func (s *SSOGroupSyncer) SetConfig(config *SSOConfig) {
	if config == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs[config.WorkspaceID] = config
}

// SyncGroups maps IdP groups to permission groups for the given workspace and
// returns which groups were added, removed, or preserved. Manual groups (those
// not matched by any mapping) are always preserved.
func (s *SSOGroupSyncer) SyncGroups(_ context.Context, workspaceID string, idpGroups []string) (*SSOSyncResult, error) {
	s.mu.RLock()
	config, ok := s.configs[workspaceID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("identity/sso: no SSO config for workspace %q", workspaceID)
	}

	result := &SSOSyncResult{}

	// Build a lookup of IdP group names for quick membership checks.
	idpSet := make(map[string]struct{}, len(idpGroups))
	for _, g := range idpGroups {
		idpSet[g] = struct{}{}
	}

	// Build a set of all permission group IDs that are managed by SSO mappings.
	managedGroups := make(map[string]struct{}, len(config.Mappings))
	for _, m := range config.Mappings {
		managedGroups[m.PermissionGroupID] = struct{}{}
	}

	// Determine which mapped groups should be active based on current IdP groups.
	activeGroups := make(map[string]struct{})
	for _, m := range config.Mappings {
		if _, present := idpSet[m.IDPGroupName]; present {
			activeGroups[m.PermissionGroupID] = struct{}{}
		}
	}

	// Added: groups that are now active from IdP assertions.
	for gid := range activeGroups {
		result.Added = append(result.Added, gid)
	}

	// Removed: managed groups that are no longer active (stale mappings).
	for gid := range managedGroups {
		if _, active := activeGroups[gid]; !active {
			result.Removed = append(result.Removed, gid)
		}
	}

	// Auto-provision: if enabled and no groups were matched, assign the default group.
	if config.AutoProvision && len(result.Added) == 0 && config.DefaultGroupID != "" {
		result.Added = append(result.Added, config.DefaultGroupID)
		result.AutoProvisioned = true
	}

	// Preserved: IdP groups that have no mapping are preserved as-is (manual groups).
	for _, g := range idpGroups {
		mapped := false
		for _, m := range config.Mappings {
			if m.IDPGroupName == g {
				mapped = true
				break
			}
		}
		if !mapped {
			result.Preserved = append(result.Preserved, g)
		}
	}

	return result, nil
}
