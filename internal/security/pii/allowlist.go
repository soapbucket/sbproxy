// Package pii detects and redacts personally identifiable information from request/response data.
package pii

import (
	"path"
	"strings"
)

// AllowlistRule defines an exemption from PII detection.
type AllowlistRule struct {
	FieldPath    string       `json:"field_path"`              // JSON field path (supports * wildcards)
	DetectorType DetectorType `json:"detector_type,omitempty"` // Specific detector or "" for all
	PathPrefix   string       `json:"path_prefix,omitempty"`   // URL path prefix where this exemption applies
}

// Allowlist holds rules that exempt certain fields from PII detection.
type Allowlist struct {
	rules []AllowlistRule
}

// NewAllowlist creates an Allowlist from a slice of rules.
func NewAllowlist(rules []AllowlistRule) *Allowlist {
	if len(rules) == 0 {
		return nil
	}
	return &Allowlist{rules: rules}
}

// IsAllowed returns true if the given field path and detector type
// are exempt from PII detection for the given request path.
func (a *Allowlist) IsAllowed(fieldPath string, detectorType DetectorType, requestPath string) bool {
	if a == nil || len(a.rules) == 0 {
		return false
	}

	for _, rule := range a.rules {
		if rule.PathPrefix != "" && !strings.HasPrefix(requestPath, rule.PathPrefix) {
			continue
		}
		if rule.DetectorType != "" && rule.DetectorType != detectorType {
			continue
		}
		if matchFieldPath(rule.FieldPath, fieldPath) {
			return true
		}
	}
	return false
}

// matchFieldPath matches a pattern against a JSON field path.
// Supports * as a single-segment wildcard and ** as a multi-segment wildcard.
func matchFieldPath(pattern, fieldPath string) bool {
	if pattern == "" || fieldPath == "" {
		return pattern == fieldPath
	}
	if pattern == "*" || pattern == "**" {
		return true
	}
	matched, _ := path.Match(pattern, fieldPath)
	return matched
}
