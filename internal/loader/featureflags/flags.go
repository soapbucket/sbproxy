// Package flags parses and propagates per-request feature flags from headers and configuration.
package featureflags

import (
	"net/http"
	"strings"
)

const (
	// HeaderFlags is the HTTP header name for flags.
	HeaderFlags = "x-sb-flags"
	// MagicParam is a constant for magic param.
	MagicParam = "_sb."
)

// disabled controls whether X-Sb-Flags and _sb.* query params are processed.
// When true, GetFlagsFromRequest returns empty flags so clients cannot control
// debug mode, cache bypass, or tracing. Set via SetDisabled at startup.
var disabled bool

// SetDisabled enables or disables sb-flags processing.
func SetDisabled(v bool) { disabled = v }

// IsDisabled reports whether sb-flags processing is disabled.
func IsDisabled() bool { return disabled }

// GetFlagsFromRequest extracts feature flags from the X-Sb-Flags header and
// _sb.* query parameters. Returns empty flags when sb-flags are disabled
// (production mode), preventing clients from controlling debug/cache/trace.
func GetFlagsFromRequest(r *http.Request) Flags {
	if disabled {
		return EmptyFlags
	}

	flags := make(Flags, 4)
	sb := r.Header.Get(HeaderFlags)

	splitChar := ","
	if strings.Contains(sb, ";") {
		splitChar = ";"
	}

	for _, flag := range strings.Split(sb, splitChar) {
		flag = strings.TrimSpace(flag)
		if flag == "" {
			continue
		}
		parts := strings.SplitN(flag, "=", 2)
		if len(parts) == 2 {
			flags[parts[0]] = strings.TrimSpace(parts[1])
		} else {
			flags[parts[0]] = ""
		}
	}

	for k, v := range r.URL.Query() {
		if strings.HasPrefix(k, MagicParam) {
			flags[k] = strings.TrimSpace(v[0])
		}
	}
	return flags
}
