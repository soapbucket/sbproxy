// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

// ThreatProtectionConfig holds JSON and XML structural validation settings
// to prevent payload-based attacks (deep nesting, key bombs, entity expansion, etc.).
type ThreatProtectionConfig struct {
	Enabled bool                    `json:"enabled"`
	JSON    *JSONThreatLimitConfig  `json:"json,omitempty"`
	XML     *XMLThreatLimitConfig   `json:"xml,omitempty"`
}

// JSONThreatLimitConfig defines structural limits for JSON request bodies.
type JSONThreatLimitConfig struct {
	MaxDepth        int `json:"max_depth"`         // default 20
	MaxKeys         int `json:"max_keys"`          // default 1000
	MaxStringLength int `json:"max_string_length"` // default 200000 (200KB)
	MaxArraySize    int `json:"max_array_size"`    // default 10000
	MaxTotalSize    int `json:"max_total_size"`    // default 10485760 (10MB)
}

// XMLThreatLimitConfig defines structural limits for XML request bodies.
type XMLThreatLimitConfig struct {
	MaxDepth             int `json:"max_depth"`              // default 20
	MaxAttributes        int `json:"max_attributes"`         // default 100
	MaxChildren          int `json:"max_children"`           // default 10000
	EntityExpansionLimit int `json:"entity_expansion_limit"` // default 0 (disabled)
}
