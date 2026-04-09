// Package flags parses and propagates per-request feature flags from headers and configuration.
package featureflags

import "strings"

// Flags is a map type for flags.
type Flags map[string]string

// EmptyFlags is a variable for empty flags.
var EmptyFlags = make(Flags)

// String returns a human-readable representation of the Flags.
func (f Flags) String() string {
	var sb strings.Builder
	for key, value := range f {
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(key)
		if value != "" {
			sb.WriteString("=")
			sb.WriteString(value)
		}
	}
	return sb.String()
}

// IsDebug reports whether the Flags is debug.
func (f Flags) IsDebug() bool {
	if value, ok := f[FlagDebug]; ok {
		return value == "true" || value == ""
	}
	return false
}

// IsTrace reports whether the Flags is trace.
func (f Flags) IsTrace() bool {
	if value, ok := f[FlagTrace]; ok {
		return value == "true" || value == ""
	}
	return false
}

// IsNoCache reports whether the Flags is no cache.
func (f Flags) IsNoCache() bool {
	if value, ok := f[FlagNoCache]; ok {
		return value == "true" || value == ""
	}
	return false
}
