// Package flags parses and propagates per-request feature flags from headers and configuration.
package featureflags

const (
	// FlagDebug is a constant for flag debug.
	FlagDebug   = "debug"
	// FlagTrace is a constant for flag trace.
	FlagTrace   = "trace"
	// FlagNoCache is a constant for flag no cache.
	FlagNoCache = "no-cache"

	// ContextKey is a constant for context key.
	ContextKey = "flags"
)
