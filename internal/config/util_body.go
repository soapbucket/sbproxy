// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import "bytes"

// isJSONBody returns true if the given byte slice looks like JSON
// (starts with '{' or '[' after trimming whitespace).
func isJSONBody(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}
