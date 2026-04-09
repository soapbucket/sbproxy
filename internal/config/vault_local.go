// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

const vaultRedisKeyPrefix = "vault:system:"

// LocalVaultProvider reads secrets from Redis using the proxy's cacher.
// The Django backend writes secrets to the same Redis keys.
type LocalVaultProvider struct {
	cache cacher.Cacher
}

// NewLocalVaultProvider creates a vault provider backed by Redis.
func NewLocalVaultProvider(cache cacher.Cacher) *LocalVaultProvider {
	return &LocalVaultProvider{cache: cache}
}

// Type performs the type operation on the LocalVaultProvider.
func (p *LocalVaultProvider) Type() VaultType {
	return VaultTypeLocal
}

// GetSecret reads a secret from Redis at "vault:system:{path}".
func (p *LocalVaultProvider) GetSecret(ctx context.Context, path string) (string, error) {
	key := vaultRedisKeyPrefix + path
	reader, err := p.cache.Get(ctx, "", key)
	if err != nil {
		slog.Debug("local vault secret not found in Redis", "path", path)
		return "", fmt.Errorf("local vault: secret not found at %q: %w", path, err)
	}
	if reader == nil {
		return "", fmt.Errorf("local vault: secret not found at %q", path)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return "", fmt.Errorf("local vault: failed to read secret at %q: %w", path, err)
	}

	return buf.String(), nil
}

// Close releases resources held by the LocalVaultProvider.
func (p *LocalVaultProvider) Close() error {
	return nil
}
