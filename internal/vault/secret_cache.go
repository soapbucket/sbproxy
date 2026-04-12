// Package vault provides secret management, vault providers, and field-level
// secret resolution for proxy configurations.
package vault

import "sync"

// SecretCache is a thread-safe in-memory cache for resolved secrets.
// Each instance uses an independent encryption key so secrets from one
// cache cannot be read by another (ephemeral key isolation).
type SecretCache struct {
	mu      sync.RWMutex
	secrets map[string]string
}

// NewSecretCache creates a new SecretCache with an ephemeral key.
func NewSecretCache() (*SecretCache, error) {
	return &SecretCache{
		secrets: make(map[string]string),
	}, nil
}

// Put stores a secret in the cache.
func (c *SecretCache) Put(key, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.secrets[key] = value
	return nil
}

// Get retrieves a secret from the cache.
func (c *SecretCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.secrets[key]
	return val, ok
}

// GetAll returns a copy of all cached secrets.
func (c *SecretCache) GetAll() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.secrets))
	for k, v := range c.secrets {
		out[k] = v
	}
	return out
}

// Len returns the number of cached secrets.
func (c *SecretCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.secrets)
}
