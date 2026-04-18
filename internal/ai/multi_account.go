// multi_account.go provides round-robin rotation across multiple provider accounts.
// This enables spreading API usage across multiple accounts for the same provider,
// with the ability to disable accounts that hit rate limits.
package ai

import (
	"sync"
	"sync/atomic"
)

// AccountConfig represents a single provider account.
type AccountConfig struct {
	Name    string `json:"name" yaml:"name"`
	APIKey  string `json:"api_key" yaml:"api_key" secret:"true"`
	OrgID   string `json:"org_id,omitempty" yaml:"org_id"`
	Weight  int    `json:"weight,omitempty" yaml:"weight"`
	Enabled bool   `json:"enabled,omitempty" yaml:"enabled"`
}

// MultiAccountManager rotates between multiple accounts for the same provider.
// Disabled accounts are skipped during rotation.
type MultiAccountManager struct {
	mu       sync.RWMutex
	accounts []AccountConfig
	index    atomic.Uint64
}

// NewMultiAccountManager creates a new account manager. Accounts with Enabled
// not explicitly set default to enabled (true).
func NewMultiAccountManager(accounts []AccountConfig) *MultiAccountManager {
	normalized := make([]AccountConfig, len(accounts))
	for i, acct := range accounts {
		normalized[i] = acct
		// Treat zero-value (false) as enabled by default if no accounts
		// have Enabled set to true.
		if !acct.Enabled && acct.APIKey != "" {
			normalized[i].Enabled = true
		}
	}
	return &MultiAccountManager{
		accounts: normalized,
	}
}

// Next returns the next account using round-robin rotation.
// Disabled accounts are skipped. Returns nil if no accounts are enabled.
func (m *MultiAccountManager) Next() *AccountConfig {
	m.mu.RLock()
	total := len(m.accounts)
	m.mu.RUnlock()

	if total == 0 {
		return nil
	}

	startIdx := m.index.Add(1) - 1

	for i := 0; i < total; i++ {
		idx := int((startIdx + uint64(i)) % uint64(total))

		m.mu.RLock()
		acct := m.accounts[idx]
		m.mu.RUnlock()

		if acct.Enabled {
			return &acct
		}
	}

	return nil
}

// GetByName returns a specific account by name. Returns nil if not found.
func (m *MultiAccountManager) GetByName(name string) *AccountConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for i := range m.accounts {
		if m.accounts[i].Name == name {
			acct := m.accounts[i]
			return &acct
		}
	}
	return nil
}

// DisableAccount marks an account as disabled (e.g., after rate limit).
func (m *MultiAccountManager) DisableAccount(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.accounts {
		if m.accounts[i].Name == name {
			m.accounts[i].Enabled = false
			return
		}
	}
}

// EnableAccount re-enables a previously disabled account.
func (m *MultiAccountManager) EnableAccount(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.accounts {
		if m.accounts[i].Name == name {
			m.accounts[i].Enabled = true
			return
		}
	}
}

// ActiveAccounts returns only enabled accounts.
func (m *MultiAccountManager) ActiveAccounts() []AccountConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var active []AccountConfig
	for _, acct := range m.accounts {
		if acct.Enabled {
			active = append(active, acct)
		}
	}
	return active
}

// Size returns the total number of accounts (enabled and disabled).
func (m *MultiAccountManager) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.accounts)
}
