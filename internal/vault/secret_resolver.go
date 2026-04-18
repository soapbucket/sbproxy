// Copyright 2026 Soap Bucket LLC. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package vault

import (
	"fmt"
	"os"
	"strings"
)

// SecretResolver resolves `secret:name`, `${ENV}`, and `file:/path` patterns.
// It wraps the existing VaultManager for `secret:` references, providing a
// higher-level abstraction that maps logical secret names to vault paths.
type SecretResolver struct {
	vaultMgr  *VaultManager
	secretMap map[string]string // logical name -> vault path
	fallback  string           // "cache", "reject", "env"
}

// NewSecretResolver creates a SecretResolver that maps logical secret names
// to vault paths and resolves them through the given VaultManager.
//
// The secretMap maps logical names (e.g., "stripe_key") to vault references
// (e.g., "system:/kv/stripe"). The fallback parameter controls behavior when
// a secret cannot be resolved: "cache" returns the last cached value, "reject"
// returns an error, and "env" falls back to environment variables.
func NewSecretResolver(vm *VaultManager, secretMap map[string]string, fallback string) *SecretResolver {
	if secretMap == nil {
		secretMap = make(map[string]string)
	}
	if fallback == "" {
		fallback = "reject"
	}
	return &SecretResolver{
		vaultMgr:  vm,
		secretMap: secretMap,
		fallback:  fallback,
	}
}

// Resolve resolves a config value. It handles the following patterns:
//   - "secret:name" - looks up name in the secret map, resolves via VaultManager
//   - "${VAR}" - resolves from environment variables
//   - "file:/path" - reads the file contents
//   - plain text - returned as-is
func (sr *SecretResolver) Resolve(value string) (string, error) {
	// Handle secret:name references
	if strings.HasPrefix(value, "secret:") {
		name := strings.TrimPrefix(value, "secret:")
		return sr.resolveSecretName(name)
	}

	// Handle ${VAR} environment variable references
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		varName := value[2 : len(value)-1]
		if varName == "" {
			return "", fmt.Errorf("secret resolver: empty environment variable name")
		}
		envVal := os.Getenv(varName)
		if envVal == "" {
			return "", fmt.Errorf("secret resolver: environment variable %q is not set", varName)
		}
		return envVal, nil
	}

	// Handle file:/path references
	if strings.HasPrefix(value, "file:") {
		path := strings.TrimPrefix(value, "file:")
		if path == "" {
			return "", fmt.Errorf("secret resolver: empty file path")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("secret resolver: failed to read file %q: %w", path, err)
		}
		return strings.TrimRight(string(data), "\n\r"), nil
	}

	// Plain text - return as-is
	return value, nil
}

// resolveSecretName looks up a logical secret name in the secret map, then
// resolves the vault path through the VaultManager.
func (sr *SecretResolver) resolveSecretName(name string) (string, error) {
	// Look up the logical name in the secret map
	vaultRef, ok := sr.secretMap[name]
	if !ok {
		return sr.handleFallback(name, fmt.Errorf("secret %q not found in secret map", name))
	}

	// The vault ref should be in "vault:path" format. The VaultManager
	// stores resolved secrets by their definition name. Check if the
	// VaultManager already has this resolved.
	if sr.vaultMgr != nil {
		// First try the logical name directly (it may have been set as a
		// secret definition on the VaultManager).
		if val, exists := sr.vaultMgr.GetSecret(name); exists {
			return val, nil
		}

		// Try the vault reference as a raw lookup key.
		if val, exists := sr.vaultMgr.GetSecret(vaultRef); exists {
			return val, nil
		}
	}

	return sr.handleFallback(name, fmt.Errorf("secret %q (ref %q) could not be resolved", name, vaultRef))
}

// handleFallback applies the configured fallback strategy when a secret
// cannot be resolved.
func (sr *SecretResolver) handleFallback(name string, resolveErr error) (string, error) {
	switch sr.fallback {
	case "cache":
		// Try to return cached value from vault manager
		if sr.vaultMgr != nil {
			if val, exists := sr.vaultMgr.GetSecret(name); exists {
				return val, nil
			}
		}
		return "", fmt.Errorf("secret resolver: %w (fallback=cache, no cached value available)", resolveErr)

	case "env":
		// Fall back to environment variable with the secret name
		envVal := os.Getenv(name)
		if envVal != "" {
			return envVal, nil
		}
		// Also try uppercase
		envVal = os.Getenv(strings.ToUpper(name))
		if envVal != "" {
			return envVal, nil
		}
		return "", fmt.Errorf("secret resolver: %w (fallback=env, env var %q not set)", resolveErr, name)

	default: // "reject"
		return "", fmt.Errorf("secret resolver: %w", resolveErr)
	}
}
