// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"fmt"
	"strings"
)

// VaultType represents the type of vault provider
type VaultType string

const (
	// VaultTypeLocal is a constant for vault type local.
	VaultTypeLocal     VaultType = "local"
	// VaultTypeHashicorp is a constant for vault type hashicorp.
	VaultTypeHashicorp VaultType = "hashicorp"
	// VaultTypeAWS is a constant for vault type aws.
	VaultTypeAWS       VaultType = "aws"
	// VaultTypeGCP is a constant for vault type gcp.
	VaultTypeGCP       VaultType = "gcp"
	// VaultTypeWebhook is a constant for vault type webhook.
	VaultTypeWebhook   VaultType = "webhook"
	// VaultTypeFile is a constant for vault type file (local JSON/YAML file).
	VaultTypeFile      VaultType = "file"
)

// VaultProvider is the interface for vault backends that retrieve secrets by path.
type VaultProvider interface {
	Type() VaultType
	GetSecret(ctx context.Context, path string) (string, error)
	Close() error
}

// VaultDefinition describes a named vault backend from the config JSON.
type VaultDefinition struct {
	Type       VaultType         `json:"type"`
	Address    string            `json:"address,omitempty"`
	AuthMethod string            `json:"auth_method,omitempty"`
	Namespace  string            `json:"namespace,omitempty"`
	Region     string            `json:"region,omitempty"`
	ProjectID  string            `json:"project_id,omitempty"`
	URL        string            `json:"url,omitempty"`
	Method     string            `json:"method,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       map[string]any    `json:"body,omitempty"`
	Timeout    string            `json:"timeout,omitempty"`

	// Credentials is a secret reference (e.g. "system:/vault/token") resolved
	// from the local vault before the remote vault is created.
	Credentials   string `json:"credentials,omitempty"`
	CacheDuration string `json:"cache_duration,omitempty"`

	// WorkspacePrefix when true prepends the origin's workspace_id to every
	// secret path resolved through this vault (e.g., "api_key" becomes
	// "ws_abc/api_key"). Enables multi-tenant secret isolation in shared vaults.
	WorkspacePrefix bool `json:"workspace_prefix,omitempty" yaml:"workspace_prefix" mapstructure:"workspace_prefix"`
}

// SecretReference is a parsed "vault:path" reference.
type SecretReference struct {
	VaultName string
	Path      string
}

// ParseSecretReference parses a secret reference string of the form "vault:path".
// Examples: "system:/gateway/cb-secret", "hashi:/kv/data/api-key"
func ParseSecretReference(ref string) (SecretReference, error) {
	idx := strings.Index(ref, ":")
	if idx < 1 {
		return SecretReference{}, fmt.Errorf("invalid secret reference %q: must be vault:path", ref)
	}
	vault := ref[:idx]
	path := ref[idx+1:]
	if path == "" {
		return SecretReference{}, fmt.Errorf("invalid secret reference %q: path cannot be empty", ref)
	}
	return SecretReference{VaultName: vault, Path: path}, nil
}
