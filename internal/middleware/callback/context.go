// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"context"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// Context keys for callback cache
type contextKey int

const (
	cacheContextKey contextKey = iota
	httpCacheContextKey
)

// WithCache adds a CallbackCache to the context
func WithCache(ctx context.Context, cache *CallbackCache) context.Context {
	if cache == nil {
		return ctx
	}
	return context.WithValue(ctx, cacheContextKey, cache)
}

// GetCache retrieves the CallbackCache from the context
// Returns nil if no cache is set in the context
func GetCache(ctx context.Context) *CallbackCache {
	if ctx == nil {
		return nil
	}

	// Fast path: check unified connection context
	if cc := reqctx.GetConnectionContext(ctx); cc != nil {
		if cache, ok := cc.CallbackCache.(*CallbackCache); ok {
			return cache
		}
	}

	// Fallback: direct context lookup
	cache, ok := ctx.Value(cacheContextKey).(*CallbackCache)
	if !ok {
		return nil
	}

	return cache
}

// WithHTTPCacheContext adds an HTTPCallbackContext to the context
func WithHTTPCacheContext(ctx context.Context, httpCtx *HTTPCallbackContext) context.Context {
	if httpCtx == nil {
		return ctx
	}
	return context.WithValue(ctx, httpCacheContextKey, httpCtx)
}

// GetHTTPCacheContext retrieves the HTTPCallbackContext from the context
// Returns nil if no HTTP cache context is set
func GetHTTPCacheContext(ctx context.Context) *HTTPCallbackContext {
	if ctx == nil {
		return nil
	}

	httpCtx, ok := ctx.Value(httpCacheContextKey).(*HTTPCallbackContext)
	if !ok {
		return nil
	}

	return httpCtx
}

