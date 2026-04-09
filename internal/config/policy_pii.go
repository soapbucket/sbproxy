// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// NewPIIPolicy creates a PIIPolicy from raw JSON configuration.
// This build provides a pass-through stub. The actual scanning logic
// must be provided by linking in a PII detection package.
func NewPIIPolicy(data []byte) (*PIIPolicy, error) {
	var p PIIPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("pii policy: %w", err)
	}
	p.PolicyType = "pii"
	return &p, nil
}

// Apply wraps the given handler with PII detection middleware.
// The open-source stub passes requests through without scanning.
func (p *PIIPolicy) Apply(next http.Handler) http.Handler {
	// Pass through in this build; no PII scanning is performed.
	return next
}
