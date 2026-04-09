// Package models defines shared data types, constants, and request/response models used across packages.
package reqctx

import (
	"context"
)

type secretsContextKey struct{}

// WithSecrets adds secrets map to the context
func WithSecrets(ctx context.Context, secrets map[string]string) context.Context {
	return context.WithValue(ctx, secretsContextKey{}, secrets)
}

// GetSecrets retrieves secrets map from the context
func GetSecrets(ctx context.Context) map[string]string {
	if secrets, ok := ctx.Value(secretsContextKey{}).(map[string]string); ok {
		return secrets
	}
	return make(map[string]string)
}

// GetSecret retrieves a single secret from the context
func GetSecret(ctx context.Context, key string) (string, bool) {
	secrets := GetSecrets(ctx)
	value, exists := secrets[key]
	return value, exists
}

