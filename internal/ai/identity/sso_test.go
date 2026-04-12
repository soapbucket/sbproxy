package identity

import (
	"context"
	"sort"
	"testing"
)

func TestSSOGroupSyncer(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name              string
		config            *SSOConfig
		idpGroups         []string
		wantAdded         []string
		wantRemoved       []string
		wantPreserved     []string
		wantAutoProvision bool
		wantErr           bool
	}{
		{
			name: "maps IdP groups to permission groups",
			config: &SSOConfig{
				WorkspaceID: "ws1",
				Mappings: []SSOGroupMapping{
					{IDPGroupName: "engineering", PermissionGroupID: "pg-eng", WorkspaceID: "ws1"},
					{IDPGroupName: "design", PermissionGroupID: "pg-design", WorkspaceID: "ws1"},
				},
			},
			idpGroups:     []string{"engineering", "design"},
			wantAdded:     []string{"pg-eng", "pg-design"},
			wantRemoved:   nil,
			wantPreserved: nil,
		},
		{
			name: "removes stale mappings",
			config: &SSOConfig{
				WorkspaceID: "ws1",
				Mappings: []SSOGroupMapping{
					{IDPGroupName: "engineering", PermissionGroupID: "pg-eng", WorkspaceID: "ws1"},
					{IDPGroupName: "design", PermissionGroupID: "pg-design", WorkspaceID: "ws1"},
					{IDPGroupName: "ops", PermissionGroupID: "pg-ops", WorkspaceID: "ws1"},
				},
			},
			idpGroups:   []string{"engineering"},
			wantAdded:   []string{"pg-eng"},
			wantRemoved: []string{"pg-design", "pg-ops"},
		},
		{
			name: "preserves manual (unmapped) groups",
			config: &SSOConfig{
				WorkspaceID: "ws1",
				Mappings: []SSOGroupMapping{
					{IDPGroupName: "engineering", PermissionGroupID: "pg-eng", WorkspaceID: "ws1"},
				},
			},
			idpGroups:     []string{"engineering", "manual-team"},
			wantAdded:     []string{"pg-eng"},
			wantPreserved: []string{"manual-team"},
		},
		{
			name: "auto-provision with default group when no mappings match",
			config: &SSOConfig{
				WorkspaceID:    "ws1",
				AutoProvision:  true,
				DefaultGroupID: "pg-default",
				Mappings: []SSOGroupMapping{
					{IDPGroupName: "admin", PermissionGroupID: "pg-admin", WorkspaceID: "ws1"},
				},
			},
			idpGroups:         []string{"unknown-group"},
			wantAdded:         []string{"pg-default"},
			wantRemoved:       []string{"pg-admin"},
			wantPreserved:     []string{"unknown-group"},
			wantAutoProvision: true,
		},
		{
			name: "auto-provision skipped when mappings match",
			config: &SSOConfig{
				WorkspaceID:    "ws1",
				AutoProvision:  true,
				DefaultGroupID: "pg-default",
				Mappings: []SSOGroupMapping{
					{IDPGroupName: "engineering", PermissionGroupID: "pg-eng", WorkspaceID: "ws1"},
				},
			},
			idpGroups:         []string{"engineering"},
			wantAdded:         []string{"pg-eng"},
			wantAutoProvision: false,
		},
		{
			name: "empty IdP groups removes all managed groups",
			config: &SSOConfig{
				WorkspaceID: "ws1",
				Mappings: []SSOGroupMapping{
					{IDPGroupName: "engineering", PermissionGroupID: "pg-eng", WorkspaceID: "ws1"},
					{IDPGroupName: "design", PermissionGroupID: "pg-design", WorkspaceID: "ws1"},
				},
			},
			idpGroups:   []string{},
			wantRemoved: []string{"pg-eng", "pg-design"},
		},
		{
			name:    "error when no config exists",
			config:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncer := NewSSOGroupSyncer()
			if tt.config != nil {
				syncer.SetConfig(tt.config)
			}

			wsID := "ws1"
			if tt.config != nil {
				wsID = tt.config.WorkspaceID
			}

			result, err := syncer.SyncGroups(ctx, wsID, tt.idpGroups)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			sortedEqual := func(label string, got, want []string) {
				t.Helper()
				if got == nil {
					got = []string{}
				}
				if want == nil {
					want = []string{}
				}
				sort.Strings(got)
				sort.Strings(want)
				if len(got) != len(want) {
					t.Errorf("%s: got %v, want %v", label, got, want)
					return
				}
				for i := range got {
					if got[i] != want[i] {
						t.Errorf("%s: got %v, want %v", label, got, want)
						return
					}
				}
			}

			sortedEqual("Added", result.Added, tt.wantAdded)
			sortedEqual("Removed", result.Removed, tt.wantRemoved)
			sortedEqual("Preserved", result.Preserved, tt.wantPreserved)

			if result.AutoProvisioned != tt.wantAutoProvision {
				t.Errorf("AutoProvisioned: got %v, want %v", result.AutoProvisioned, tt.wantAutoProvision)
			}
		})
	}
}

func TestSSOGroupSyncer_SetConfig(t *testing.T) {
	syncer := NewSSOGroupSyncer()

	// Setting nil should not panic.
	syncer.SetConfig(nil)

	config := &SSOConfig{
		WorkspaceID: "ws-test",
		Mappings: []SSOGroupMapping{
			{IDPGroupName: "devs", PermissionGroupID: "pg-devs", WorkspaceID: "ws-test"},
		},
	}
	syncer.SetConfig(config)

	// Overwrite existing config.
	updated := &SSOConfig{
		WorkspaceID:    "ws-test",
		AutoProvision:  true,
		DefaultGroupID: "pg-new-default",
		Mappings: []SSOGroupMapping{
			{IDPGroupName: "devs", PermissionGroupID: "pg-devs-v2", WorkspaceID: "ws-test"},
		},
	}
	syncer.SetConfig(updated)

	result, err := syncer.SyncGroups(context.Background(), "ws-test", []string{"devs"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Added) != 1 || result.Added[0] != "pg-devs-v2" {
		t.Errorf("expected updated mapping pg-devs-v2, got %v", result.Added)
	}
}
