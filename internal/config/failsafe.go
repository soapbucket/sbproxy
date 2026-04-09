// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import "encoding/json"

// FailsafeOrigin configures an explicit degraded-mode origin to load when the
// intended config cannot be loaded safely.
type FailsafeOrigin struct {
	Hostname     string          `json:"hostname"`
	Origin       json.RawMessage `json:"origin,omitempty"`
	ReasonHeader bool            `json:"reason_header,omitempty"`
}

// HasEmbeddedOrigin reports whether the FailsafeOrigin has embedded origin.
func (f *FailsafeOrigin) HasEmbeddedOrigin() bool {
	return f != nil && len(f.Origin) > 0
}
