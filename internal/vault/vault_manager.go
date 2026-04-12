// Package vault provides secret management, vault providers, and field-level
// secret resolution for proxy configurations.
package vault

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// secretRefPattern matches {{secrets.NAME}} placeholders used in vault interpolation.
var secretRefPattern = regexp.MustCompile(`\{\{secrets\.([A-Za-z0-9_]+)\}\}`)

// VaultManager orchestrates multi-vault secret resolution. It holds a local
// (system) vault provider and zero or more named remote vault providers.
// Secret definitions map friendly names to "vault:path" references which are
// resolved in bulk via ResolveAll and cached for fast GetSecret lookups.
type VaultManager struct {
	mu           sync.RWMutex
	localVault   VaultProvider
	remoteVaults map[string]VaultProvider

	// secretDefs maps secret names to "vault:path" references (e.g. "system:/gateway/key").
	secretDefs map[string]string

	// resolved holds the cached secret values after ResolveAll.
	resolved map[string]string

	// cache provides encrypted at-rest storage for resolved secrets.
	cache *SecretCache
}

// NewVaultManager creates a VaultManager with the given local vault provider.
func NewVaultManager(localVault VaultProvider) (*VaultManager, error) {
	if localVault == nil {
		return nil, fmt.Errorf("vault manager: local vault provider must not be nil")
	}
	cache, err := NewSecretCache()
	if err != nil {
		return nil, fmt.Errorf("vault manager: failed to create secret cache: %w", err)
	}
	return &VaultManager{
		localVault:   localVault,
		remoteVaults: make(map[string]VaultProvider),
		secretDefs:   make(map[string]string),
		resolved:     make(map[string]string),
		cache:        cache,
	}, nil
}

// SetVaultDefinitions stores the merged vault definitions so that ResolveAll
// can create remote providers as needed. In the open-source build the
// definitions are stored but remote vault creation is not implemented.
func (vm *VaultManager) SetVaultDefinitions(defs map[string]VaultDefinition) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	// Store definitions for potential future use; remote provider creation
	// is not implemented in this build.
	_ = defs
}

// SetWorkspaceID associates a workspace with the vault manager so that
// workspace-prefixed secret paths can be resolved. In the open-source build
// this is a no-op.
func (vm *VaultManager) SetWorkspaceID(workspaceID string) {
	_ = workspaceID
}

// SetSecretDefinitions sets the secret name to "vault:path" mapping that
// ResolveAll will resolve.
func (vm *VaultManager) SetSecretDefinitions(defs map[string]string) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.secretDefs = defs
}

// ResolveAll resolves every secret definition by looking up the referenced
// vault provider and fetching the secret at the given path. Results are cached
// for subsequent GetSecret calls.
func (vm *VaultManager) ResolveAll(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	resolved := make(map[string]string, len(vm.secretDefs))

	for name, ref := range vm.secretDefs {
		parsed, err := ParseSecretReference(ref)
		if err != nil {
			return fmt.Errorf("vault manager: secret %q: %w", name, err)
		}

		provider, err := vm.providerForVault(parsed.VaultName)
		if err != nil {
			return fmt.Errorf("vault manager: secret %q: %w", name, err)
		}

		value, err := provider.GetSecret(ctx, parsed.Path)
		if err != nil {
			return fmt.Errorf("vault manager: failed to resolve secret %q from %s:%s: %w",
				name, parsed.VaultName, parsed.Path, err)
		}

		resolved[name] = value
	}

	vm.resolved = resolved

	// Also populate the cache for consumers that read from it.
	if vm.cache != nil {
		for k, v := range resolved {
			if err := vm.cache.Put(k, v); err != nil {
				return fmt.Errorf("vault manager: failed to cache secret %q: %w", k, err)
			}
		}
	}

	return nil
}

// providerForVault returns the vault provider for the given vault name.
// "system" maps to the local vault; all other names are looked up in remoteVaults.
// Caller must hold vm.mu.
func (vm *VaultManager) providerForVault(name string) (VaultProvider, error) {
	if name == "system" {
		return vm.localVault, nil
	}
	provider, ok := vm.remoteVaults[name]
	if !ok {
		return nil, fmt.Errorf("unknown vault %q", name)
	}
	return provider, nil
}

// GetSecret returns a previously resolved secret by name and whether it exists.
// It checks the encrypted cache first, then the resolved map.
func (vm *VaultManager) GetSecret(name string) (string, bool) {
	// Check cache first (populated by ResolveAll or directly in tests).
	if vm.cache != nil {
		if val, ok := vm.cache.Get(name); ok {
			return val, true
		}
	}
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	val, ok := vm.resolved[name]
	return val, ok
}

// GetAllSecrets returns a copy of all resolved secrets.
func (vm *VaultManager) GetAllSecrets() map[string]string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	out := make(map[string]string, len(vm.resolved))
	for k, v := range vm.resolved {
		out[k] = v
	}
	return out
}

// createRemoteProvider creates a VaultProvider for the given vault definition.
// It resolves credential references from the local vault before creating the
// remote provider. Currently only HashiCorp Vault with token auth is supported.
func (vm *VaultManager) createRemoteProvider(ctx context.Context, name string, def VaultDefinition, resolvedSecrets map[string]string) (VaultProvider, error) {
	// Resolve credentials from local vault if it's a system: reference
	cred := def.Credentials
	if cred != "" {
		ref, err := ParseSecretReference(cred)
		if err != nil {
			return nil, fmt.Errorf("create remote provider %q: invalid credentials ref: %w", name, err)
		}
		provider, err := vm.providerForVault(ref.VaultName)
		if err != nil {
			return nil, fmt.Errorf("create remote provider %q: %w", name, err)
		}
		resolved, err := provider.GetSecret(ctx, ref.Path)
		if err != nil {
			return nil, fmt.Errorf("create remote provider %q: failed to resolve credentials: %w", name, err)
		}
		cred = resolved
	}

	switch def.Type {
	case VaultTypeHashicorp:
		if def.AuthMethod != "" && def.AuthMethod != "token" {
			return nil, fmt.Errorf("create remote provider %q: unsupported auth_method %q (only \"token\" is supported)", name, def.AuthMethod)
		}
		return NewHashicorpVaultProvider(def, cred)
	default:
		return nil, fmt.Errorf("create remote provider %q: unsupported vault type %q", name, def.Type)
	}
}

// Close releases resources held by all vault providers.
func (vm *VaultManager) Close() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	var errs []string
	if vm.localVault != nil {
		if err := vm.localVault.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("local vault: %v", err))
		}
	}
	for name, prov := range vm.remoteVaults {
		if err := prov.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("vault %s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("vault manager close errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// interpolateSecretRefs replaces {{secrets.NAME}} placeholders in the input
// string with values from the provided secrets map. Unmatched placeholders are
// left as-is.
func interpolateSecretRefs(input string, secrets map[string]string) string {
	return secretRefPattern.ReplaceAllStringFunc(input, func(match string) string {
		matches := secretRefPattern.FindStringSubmatch(match)
		if len(matches) < 2 {
			return match
		}
		if val, ok := secrets[matches[1]]; ok {
			return val
		}
		return match
	})
}
