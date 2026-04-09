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
	MagicParam  = "_sb."
)

// GetFlagsFromRequest returns the flags from request.
func GetFlagsFromRequest(r *http.Request) Flags {
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
