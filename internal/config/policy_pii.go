// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// NewPIIPolicy creates a PIIPolicy from raw JSON configuration.
// In the open-source build this returns an error indicating PII detection
// is an enterprise feature. The stub exists so that tests compile; the
// actual scanning logic lives in the enterprise module.
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
	// Enterprise feature - pass through in open-source build.
	return next
}
