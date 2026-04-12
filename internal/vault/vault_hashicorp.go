// Package vault provides secret management, vault providers, and field-level
// secret resolution for proxy configurations.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	vaultTokenHeader     = "X-Vault-Token"
	vaultNamespaceHeader = "X-Vault-Namespace"
)

// HashicorpVaultProvider implements VaultProvider for HashiCorp Vault.
type HashicorpVaultProvider struct {
	address   string
	token     string
	namespace string
	client    *http.Client
}

// NewHashicorpVaultProvider creates a provider for HashiCorp Vault.
func NewHashicorpVaultProvider(def VaultDefinition, token string) (*HashicorpVaultProvider, error) {
	if def.Address == "" {
		return nil, fmt.Errorf("hashicorp vault: address is required")
	}
	return &HashicorpVaultProvider{
		address:   strings.TrimRight(def.Address, "/"),
		token:     token,
		namespace: def.Namespace,
		client:    newHTTPClientWithTimeout(30 * time.Second),
	}, nil
}

// Type returns VaultTypeHashicorp.
func (h *HashicorpVaultProvider) Type() VaultType {
	return VaultTypeHashicorp
}

// GetSecret retrieves a secret from HashiCorp Vault.
// The path format is "mount/path" or "mount/path#field" for field selection.
func (h *HashicorpVaultProvider) GetSecret(ctx context.Context, path string) (string, error) {
	// Parse optional field selector
	field := "value"
	if idx := strings.Index(path, "#"); idx >= 0 {
		field = path[idx+1:]
		path = path[:idx]
	}

	url := fmt.Sprintf("%s/v1/%s", h.address, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("hashicorp vault: %w", err)
	}

	req.Header.Set(vaultTokenHeader, h.token)
	if h.namespace != "" {
		req.Header.Set(vaultNamespaceHeader, h.namespace)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("hashicorp vault: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("hashicorp vault: HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("hashicorp vault: read body: %w", err)
	}

	// Parse the KV v2 response: {"data":{"data":{...}}}
	var envelope struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("hashicorp vault: parse response: %w", err)
	}

	return extractFieldFromString(mustJSON(envelope.Data.Data), field, "hashicorp")
}

// Close releases resources held by the provider.
func (h *HashicorpVaultProvider) Close() error {
	return nil
}

// mustJSON marshals a value to JSON string, returning "{}" on error.
func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
