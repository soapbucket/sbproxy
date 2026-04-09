// Package manager defines the Manager interface for coordinating proxy lifecycle and configuration reloads.
package manager

import (
	"context"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// GetManager returns the manager.
func GetManager(ctx context.Context) Manager {
	// Fast path: check unified connection context
	if cc := reqctx.GetConnectionContext(ctx); cc != nil {
		if m, ok := cc.Manager.(Manager); ok {
			return m
		}
	}
	// Fallback: direct context lookup
	if val, ok := ctx.Value(ManagerKey).(Manager); ok {
		return val
	}
	return nil
}

// SetManager performs the set manager operation.
func SetManager(ctx context.Context, manager Manager) context.Context {
	return context.WithValue(ctx, ManagerKey, manager)
}
