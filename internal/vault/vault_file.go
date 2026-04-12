// Package vault provides secret management, vault providers, and field-level
// secret resolution for proxy configurations.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"gopkg.in/yaml.v3"
)

// FileVaultProvider reads secrets from a local JSON or YAML file.
// Values are either plaintext or encrypted with a local: prefix when
// an encryption key is configured.
type FileVaultProvider struct {
	secrets map[string]string
}

// NewFileVaultProvider creates a vault provider that reads secrets from a file.
// The file must contain a flat map of string keys to string values.
// If the VaultDefinition.Credentials field is set, it is treated as a
// base64-encoded AES-256 encryption key and each value with a "local:" prefix
// is decrypted on load.
func NewFileVaultProvider(def VaultDefinition) (*FileVaultProvider, error) {
	filePath := def.Address
	if filePath == "" {
		return nil, fmt.Errorf("file vault: address (file path) is required")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("file vault: failed to read file %q: %w", filePath, err)
	}

	raw := make(map[string]string)
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("file vault: failed to parse JSON file %q: %w", filePath, err)
		}
	case ".yml", ".yaml":
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("file vault: failed to parse YAML file %q: %w", filePath, err)
		}
	default:
		return nil, fmt.Errorf("file vault: unsupported file extension %q (use .json, .yml, or .yaml)", ext)
	}

	// If an encryption key is provided, decrypt values with the local: prefix.
	if strings.TrimSpace(def.Credentials) != "" {
		c, err := crypto.NewCrypto(crypto.Settings{
			Driver: "local",
			Params: map[string]string{
				crypto.ParamEncryptionKey: def.Credentials,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("file vault: failed to create crypto for decryption: %w", err)
		}
		for k, v := range raw {
			if crypto.IsEncrypted(v) {
				plaintext, err := c.Decrypt([]byte(v))
				if err != nil {
					return nil, fmt.Errorf("file vault: failed to decrypt key %q: %w", k, err)
				}
				raw[k] = string(plaintext)
			}
		}
	}

	return &FileVaultProvider{secrets: raw}, nil
}

// Type returns VaultTypeFile.
func (p *FileVaultProvider) Type() VaultType {
	return VaultTypeFile
}

// GetSecret retrieves a secret by key from the in-memory map.
func (p *FileVaultProvider) GetSecret(_ context.Context, path string) (string, error) {
	val, ok := p.secrets[path]
	if !ok {
		return "", fmt.Errorf("file vault: secret %q not found", path)
	}
	return val, nil
}

// Close is a no-op for the file vault provider.
func (p *FileVaultProvider) Close() error {
	return nil
}
