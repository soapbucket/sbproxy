// Package models defines shared data types, constants, and request/response models used across packages.
package reqctx

import "context"

// ConnectionContext holds per-connection data in a single struct
// stored once in context.Context to minimize context.WithValue allocations.
// Fields use 'any' type to avoid import cycles with manager/callback/fingerprint packages.
type ConnectionContext struct {
	Manager          any // manager.Manager
	CallbackCache    any // *callback.CallbackCache
	ConnectionTiming any // *fingerprint.ConnectionTiming or *fingerprint.QUICConnectionTiming
}

type connCtxKey struct{}

// SetConnectionContext stores a ConnectionContext in the given context.
func SetConnectionContext(ctx context.Context, cc *ConnectionContext) context.Context {
	return context.WithValue(ctx, connCtxKey{}, cc)
}

// GetConnectionContext retrieves the ConnectionContext from the given context.
func GetConnectionContext(ctx context.Context) *ConnectionContext {
	if cc, ok := ctx.Value(connCtxKey{}).(*ConnectionContext); ok {
		return cc
	}
	return nil
}
