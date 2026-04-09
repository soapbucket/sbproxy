// Package hostfilter matches incoming requests to origin configurations based on hostname patterns.
package hostfilter

import (
	"context"
)

// LoadHostnames loads all hostname keys from storage for populating the bloom filter.
// If workspaceID is non-empty, only hostnames belonging to that workspace are returned.
func LoadHostnames(ctx context.Context, s StorageKeyLister) ([]string, error) {
	return s.ListKeys(ctx)
}

// LoadHostnamesByWorkspace loads hostname keys for a specific workspace.
func LoadHostnamesByWorkspace(ctx context.Context, s StorageKeyLister, workspaceID string) ([]string, error) {
	return s.ListKeysByWorkspace(ctx, workspaceID)
}
