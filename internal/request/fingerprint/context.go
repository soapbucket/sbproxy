// Package fingerprint generates TLS and HTTP fingerprints (JA3, JA4) for client identification.
package fingerprint

import (
	"context"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// AddConnectionTimingToContext adds ConnectionTiming to a Go context (for use in ConnContext callbacks)
func AddConnectionTimingToContext(ctx context.Context, timing *ConnectionTiming) context.Context {
	return context.WithValue(ctx, contextKeyConnectionTiming, timing)
}

// GetConnectionTimingFromContext retrieves ConnectionTiming from a Go context
func GetConnectionTimingFromContext(ctx context.Context) *ConnectionTiming {
	if ctx == nil {
		return nil
	}
	// Fast path: check unified connection context
	if cc := reqctx.GetConnectionContext(ctx); cc != nil {
		if timing, ok := cc.ConnectionTiming.(*ConnectionTiming); ok {
			return timing
		}
	}
	// Fallback: direct context lookup
	if timing, ok := ctx.Value(contextKeyConnectionTiming).(*ConnectionTiming); ok {
		return timing
	}
	return nil
}

// AddQUICConnectionTimingToContext adds QUICConnectionTiming to a Go context (for use in HTTP/3 ConnContext callbacks)
func AddQUICConnectionTimingToContext(ctx context.Context, timing *QUICConnectionTiming) context.Context {
	return context.WithValue(ctx, contextKeyConnectionTiming, timing)
}

// GetQUICConnectionTimingFromContext retrieves QUICConnectionTiming from a Go context
func GetQUICConnectionTimingFromContext(ctx context.Context) *QUICConnectionTiming {
	if ctx == nil {
		return nil
	}
	// Fast path: check unified connection context
	if cc := reqctx.GetConnectionContext(ctx); cc != nil {
		if timing, ok := cc.ConnectionTiming.(*QUICConnectionTiming); ok {
			return timing
		}
	}
	// Fallback: direct context lookup
	if timing, ok := ctx.Value(contextKeyConnectionTiming).(*QUICConnectionTiming); ok {
		return timing
	}
	return nil
}
