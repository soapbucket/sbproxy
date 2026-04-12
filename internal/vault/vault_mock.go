// Package vault provides secret management, vault providers, and field-level
// secret resolution for proxy configurations.
package vault

import (
	"context"
	"fmt"
	"sync"
)

// MockVaultProvider is an in-memory vault for testing.
type MockVaultProvider struct {
	mu      sync.RWMutex
	secrets map[string]string
	vtype   VaultType
}

// NewMockVaultProvider creates a mock vault of the given type.
func NewMockVaultProvider(vtype VaultType) *MockVaultProvider {
	return &MockVaultProvider{
		secrets: make(map[string]string),
		vtype:   vtype,
	}
}

// Type performs the type operation on the MockVaultProvider.
func (m *MockVaultProvider) Type() VaultType {
	return m.vtype
}

// SetSecret sets a secret in the mock vault (for test setup).
func (m *MockVaultProvider) SetSecret(path, value string) {
	m.mu.Lock()
	m.secrets[path] = value
	m.mu.Unlock()
}

// GetSecret retrieves a secret from the mock vault.
func (m *MockVaultProvider) GetSecret(_ context.Context, path string) (string, error) {
	m.mu.RLock()
	val, ok := m.secrets[path]
	m.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("mock vault: secret not found at %q", path)
	}
	return val, nil
}

// Close releases resources held by the MockVaultProvider.
func (m *MockVaultProvider) Close() error {
	return nil
}
