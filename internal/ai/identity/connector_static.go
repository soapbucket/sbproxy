package identity

import (
	"context"
	"sync"
	"time"
)

// StaticConnector resolves permissions from an in-memory map loaded from config.
type StaticConnector struct {
	mu          sync.RWMutex
	permissions map[string]*CachedPermission // key: "type:credential"
}

// NewStaticConnector creates a static permission connector from the given entries.
func NewStaticConnector(perms []StaticPermission) *StaticConnector {
	s := &StaticConnector{}
	s.loadPermissions(perms)
	return s
}

// Resolve looks up a credential in the static permission map.
// Returns nil, nil if the credential is not found.
func (s *StaticConnector) Resolve(_ context.Context, credentialType, credential string) (*CachedPermission, error) {
	key := credentialType + ":" + credential
	s.mu.RLock()
	defer s.mu.RUnlock()

	perm, ok := s.permissions[key]
	if !ok {
		return nil, nil
	}

	// Return a copy with fresh timestamps.
	now := time.Now()
	result := &CachedPermission{
		Principal:   perm.Principal,
		Groups:      perm.Groups,
		Models:      perm.Models,
		Permissions: perm.Permissions,
		CachedAt:    now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}
	return result, nil
}

// Reload replaces the entire permission set atomically.
func (s *StaticConnector) Reload(perms []StaticPermission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadPermissionsLocked(perms)
}

// loadPermissions builds the permission map (acquires write lock).
func (s *StaticConnector) loadPermissions(perms []StaticPermission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadPermissionsLocked(perms)
}

// loadPermissionsLocked builds the permission map (caller must hold write lock).
func (s *StaticConnector) loadPermissionsLocked(perms []StaticPermission) {
	m := make(map[string]*CachedPermission, len(perms))
	for _, p := range perms {
		key := p.Type + ":" + p.Credential
		m[key] = &CachedPermission{
			Principal:   p.Principal,
			Groups:      p.Groups,
			Models:      p.Models,
			Permissions: p.Permissions,
		}
	}
	s.permissions = m
}
